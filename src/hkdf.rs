// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

use crate::hash::{Algorithm as HashAlgorithm, SHA256, SHA384};
use once_cell::sync::Lazy;
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Hmac as _, Tag};
use rustls::crypto::tls13::{
    Hkdf as RustlsHkdf, HkdfExpander as RustlsHkdfExpander, HkdfUsingHmac, OkmBlock,
    OutputLengthError,
};
use windows::core::{Owned, PCWSTR};
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCryptBuffer, BCryptBufferDesc, BCryptGenerateSymmetricKey, BCryptKeyDerivation,
    BCryptSetProperty as Win32BCryptSetProperty, BCRYPTBUFFER_VERSION, BCRYPT_HANDLE,
    BCRYPT_HKDF_ALG_HANDLE, BCRYPT_HKDF_HASH_ALGORITHM, BCRYPT_HKDF_PRK_AND_FINALIZE,
    BCRYPT_HKDF_SALT_AND_FINALIZE, BCRYPT_KEY_HANDLE, KDF_HKDF_INFO,
};

// Follows instructions at https://github.com/kdschlosser/pyWinAPI/blob/43e0be2dfe80aa701e01f43b806d1e8e52c3c221/shared/bcrypt_h.py#L637
// for using the BCrypt HKDF API.

static CNG_SUPPORTS_HKDF: Lazy<bool> = Lazy::new(probe_cng_hkdf);

/// HKDF implementation for the specified hash algorithm.
///
/// Uses the CNG HKDF algorithm when the host supports it. Otherwise, composes HKDF from CNG HMAC
/// with [`HkdfUsingHmac`].
#[derive(Debug, Copy, Clone)]
pub(crate) struct Hkdf<const HASH_SIZE: usize> {
    hash: HashAlgorithm<HASH_SIZE>,
    #[cfg(test)]
    force_fallback: bool,
}

impl<const HASH_SIZE: usize> Hkdf<HASH_SIZE> {
    pub(crate) const fn new(hash: HashAlgorithm<HASH_SIZE>) -> Self {
        Self {
            hash,
            #[cfg(test)]
            force_fallback: false,
        }
    }

    /// Returns an HKDF that always uses the HMAC fallback, so tests can exercise it on hosts that
    /// support CNG HKDF.
    #[cfg(test)]
    pub(crate) const fn fallback(hash: HashAlgorithm<HASH_SIZE>) -> Self {
        Self {
            hash,
            force_fallback: true,
        }
    }

    fn uses_native(&self) -> bool {
        #[cfg(test)]
        if self.force_fallback {
            return false;
        }
        cng_supports_hkdf()
    }

    fn hmac_hkdf(&self) -> HkdfUsingHmac<'_> {
        HkdfUsingHmac(&self.hash)
    }
}

/// Returns whether the host CNG implementation provides the HKDF algorithm.
pub(crate) fn cng_supports_hkdf() -> bool {
    *CNG_SUPPORTS_HKDF
}

fn probe_cng_hkdf() -> bool {
    // Windows Server 2016 (build 14393) CNG has no HKDF algorithm. There, BCRYPT_HKDF_ALG_HANDLE
    // is not a valid pseudo-handle, and key creation fails with STATUS_INVALID_HANDLE. Run a full
    // extract and expand for each hash that the cipher suites use, and use the CNG HKDF only on
    // hosts where all of them succeed.
    fn probe<const HASH_SIZE: usize>(hash: HashAlgorithm<HASH_SIZE>) -> bool {
        let Ok(key_handle) = native_extract(hash, None, &[0u8; HASH_SIZE]) else {
            return false;
        };
        let expander = HkdfExpander { key_handle, hash };
        let mut output = [0u8; HASH_SIZE];
        expander.expand_slice(&[b"probe"], &mut output).is_ok()
    }

    probe(SHA256) && probe(SHA384)
}

/// Runs CNG HKDF-Extract and returns a key handle that is ready for HKDF-Expand.
fn native_extract<const HASH_SIZE: usize>(
    hash: HashAlgorithm<HASH_SIZE>,
    salt: Option<&[u8]>,
    secret: &[u8],
) -> windows::core::Result<Owned<BCRYPT_KEY_HANDLE>> {
    let mut key_handle = Owned::default();

    unsafe {
        BCryptGenerateSymmetricKey(BCRYPT_HKDF_ALG_HANDLE, &mut *key_handle, None, secret, 0)
            .ok()?;
        let bcrypt_handle = BCRYPT_HANDLE(&mut *key_handle.0);
        Win32BCryptSetProperty(bcrypt_handle, BCRYPT_HKDF_HASH_ALGORITHM, hash.id_bytes, 0).ok()?;

        Win32BCryptSetProperty(
            bcrypt_handle,
            BCRYPT_HKDF_SALT_AND_FINALIZE,
            salt.unwrap_or(&[0u8; HASH_SIZE]),
            0,
        )
        .ok()?;
    };

    Ok(key_handle)
}

/// Imports a pseudorandom key into CNG HKDF and returns a key handle that is ready for
/// HKDF-Expand.
fn native_expander_for_okm<const HASH_SIZE: usize>(
    hash: HashAlgorithm<HASH_SIZE>,
    okm: &[u8],
) -> windows::core::Result<Owned<BCRYPT_KEY_HANDLE>> {
    let mut key_handle = Owned::default();

    unsafe {
        BCryptGenerateSymmetricKey(BCRYPT_HKDF_ALG_HANDLE, &mut *key_handle, None, okm, 0).ok()?;

        let bcrypt_handle = BCRYPT_HANDLE(&mut *key_handle.0);
        Win32BCryptSetProperty(bcrypt_handle, BCRYPT_HKDF_HASH_ALGORITHM, hash.id_bytes, 0).ok()?;

        // Use extern fn directly to pass a null pointer
        BCryptSetProperty(
            bcrypt_handle,
            BCRYPT_HKDF_PRK_AND_FINALIZE,
            std::ptr::null(),
            0,
            0,
        )
        .ok()?;
    };

    Ok(key_handle)
}

struct HkdfExpander<const HASH_SIZE: usize> {
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    hash: HashAlgorithm<HASH_SIZE>,
}

unsafe impl<const HASH_SIZE: usize> Send for HkdfExpander<HASH_SIZE> {}
unsafe impl<const HASH_SIZE: usize> Sync for HkdfExpander<HASH_SIZE> {}

impl<const HASH_SIZE: usize> RustlsHkdf for Hkdf<HASH_SIZE> {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn RustlsHkdfExpander> {
        let secret = [0u8; HASH_SIZE];
        self.extract_from_secret(salt, &secret)
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn RustlsHkdfExpander> {
        if !self.uses_native() {
            return self.hmac_hkdf().extract_from_secret(salt, secret);
        }

        // The capability probe passed, so CNG HKDF errors here are unexpected.
        let key_handle = native_extract(self.hash, salt, secret).expect("CNG HKDF-Extract failed");
        Box::new(HkdfExpander::<HASH_SIZE> {
            key_handle,
            hash: self.hash,
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn RustlsHkdfExpander> {
        if !self.uses_native() {
            return self.hmac_hkdf().expander_for_okm(okm);
        }

        // The capability probe passed, so CNG HKDF errors here are unexpected.
        let key_handle =
            native_expander_for_okm(self.hash, okm.as_ref()).expect("CNG HKDF PRK import failed");
        Box::new(HkdfExpander::<HASH_SIZE> {
            key_handle,
            hash: self.hash,
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        // CNG HMAC is available on all supported hosts, so both paths use it.
        self.hash.with_key(key.as_ref()).sign(&[message])
    }

    fn fips(&self) -> bool {
        // The HMAC fallback composes HKDF outside of the CNG key derivation function. Only the CNG
        // HKDF reports FIPS status.
        self.uses_native() && crate::fips::enabled()
    }
}

// required for passing null pointer when setting HDKF_PRK_AND_FINALIZE
// can be removed if switched to windows-sys
extern "system" {
    fn BCryptSetProperty(
        hobject: BCRYPT_HANDLE,
        pszproperty: PCWSTR,
        pbinput: *const u8,
        cbinput: u32,
        dwflags: u32,
    ) -> NTSTATUS;
}

impl<const HASH_SIZE: usize> RustlsHkdfExpander for HkdfExpander<HASH_SIZE> {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        // BCrypt expects a single info buffer
        let info = info
            .iter()
            .flat_map(|info| info.iter())
            .copied()
            .collect::<Vec<u8>>();
        let mut buffer = BCryptBuffer {
            cbBuffer: info.len() as u32,
            BufferType: KDF_HKDF_INFO,
            pvBuffer: info.as_ptr() as *mut _,
        };

        let params = if info.is_empty() {
            BCryptBufferDesc::default()
        } else {
            BCryptBufferDesc {
                ulVersion: BCRYPTBUFFER_VERSION,
                cBuffers: 1u32,
                pBuffers: &mut buffer,
            }
        };

        let mut size = 0u32;
        unsafe {
            BCryptKeyDerivation(*self.key_handle, Some(&params), output, &mut size, 0)
                .ok()
                .map_err(|_| OutputLengthError)?;
        };
        if size != output.len() as u32 {
            return Err(OutputLengthError);
        }
        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = [0u8; HASH_SIZE];
        self.expand_slice(info, &mut output)
            .expect("HDKF-Expand failed");
        OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        self.hash.output_len()
    }
}

#[cfg(test)]
mod test {
    use rustls::crypto::hmac::Hmac as _;
    use rustls::crypto::tls13::{Hkdf as _, OkmBlock};
    use wycheproof::{hkdf::TestName, TestResult};

    use super::Hkdf;
    use crate::hash::{SHA256, SHA384};

    fn test_hkdf<const HASH_SIZE: usize>(hkdf: Hkdf<HASH_SIZE>, test_name: TestName) {
        let test_set = wycheproof::hkdf::TestSet::load(test_name).unwrap();

        for test_group in test_set.test_groups {
            for test in test_group.tests {
                dbg!(&test);

                // HKDF-Extract is HMAC(salt, IKM). Compute the PRK with CNG HMAC so that the
                // same vectors also cover `expander_for_okm`.
                let prk = hkdf.hash.with_key(&test.salt).sign(&[&test.ikm]);
                let expanders = [
                    hkdf.extract_from_secret(Some(&test.salt), &test.ikm),
                    hkdf.expander_for_okm(&OkmBlock::new(prk.as_ref())),
                ];

                let infos = test.info.chunks(2).collect::<Vec<_>>();

                for expander in expanders {
                    let mut okm = vec![0; test.size];
                    let res = expander.expand_slice(&infos, &mut okm);

                    match &test.result {
                        TestResult::Acceptable | TestResult::Valid => {
                            assert!(res.is_ok());
                            assert_eq!(okm[..], test.okm[..], "Failed test: {}", test.comment);
                        }
                        TestResult::Invalid => {
                            dbg!(&res);
                            assert!(res.is_err(), "Failed test: {}", test.comment);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn hkdf_sha256() {
        test_hkdf(Hkdf::new(SHA256), TestName::HkdfSha256);
    }

    #[test]
    fn hkdf_sha384() {
        test_hkdf(Hkdf::new(SHA384), TestName::HkdfSha384);
    }

    #[test]
    fn hkdf_fallback_sha256() {
        test_hkdf(Hkdf::fallback(SHA256), TestName::HkdfSha256);
    }

    #[test]
    fn hkdf_fallback_sha384() {
        test_hkdf(Hkdf::fallback(SHA384), TestName::HkdfSha384);
    }

    #[test]
    fn hkdf_capability_probe_does_not_panic() {
        let _supported = std::panic::catch_unwind(super::probe_cng_hkdf)
            .expect("HKDF capability probing should return false instead of panicking");
    }

    #[test]
    fn hkdf_fallback_is_not_fips() {
        assert!(!Hkdf::fallback(SHA256).fips());
        assert!(!Hkdf::fallback(SHA384).fips());
    }

    #[test]
    fn hkdf_fips_requires_cng_hkdf() {
        let expected = super::cng_supports_hkdf() && crate::fips::enabled();
        assert_eq!(Hkdf::new(SHA256).fips(), expected);
        assert_eq!(Hkdf::new(SHA384).fips(), expected);
    }

    #[test]
    fn hkdf_fallback_matches_cng_hkdf() {
        if !super::cng_supports_hkdf() {
            return;
        }

        let native = Hkdf::new(SHA384);
        let fallback = Hkdf::fallback(SHA384);
        let salt = [0x5au8; 48];
        let info: &[&[u8]] = &[b"tls13 ", b"derived"];

        for salt in [None, Some(&salt[..])] {
            let native_okm = native.extract_from_zero_ikm(salt).expand_block(info);
            let fallback_okm = fallback.extract_from_zero_ikm(salt).expand_block(info);
            assert_eq!(native_okm.as_ref(), fallback_okm.as_ref());
        }
    }
}
