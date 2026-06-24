// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

use rustls::crypto::cipher::NONCE_LEN;
use rustls::Error;
use windows::core::Owned;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCryptGenerateSymmetricKey, BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_ALG_HANDLE,
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
    BCRYPT_CHACHA20_POLY1305_ALG_HANDLE, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE,
};

/// The tag length is 16 bytes for all supported ciphers.
pub(crate) const TAG_LEN: usize = 16;

type BcryptInPlaceFn = unsafe fn(
    BCRYPT_KEY_HANDLE,
    *mut u8,
    u32,
    *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    *mut u32,
    BCRYPT_FLAGS,
) -> NTSTATUS;

const _: BcryptInPlaceFn = bcrypt_encrypt_in_place;
const _: BcryptInPlaceFn = bcrypt_decrypt_in_place;

#[link(name = "bcrypt")]
extern "system" {
    #[link_name = "BCryptEncrypt"]
    fn bcrypt_encrypt_raw(
        hkey: BCRYPT_KEY_HANDLE,
        pbinput: *const u8,
        cbinput: u32,
        ppaddinginfo: *const core::ffi::c_void,
        pbiv: *mut u8,
        cbiv: u32,
        pboutput: *mut u8,
        cboutput: u32,
        pcbresult: *mut u32,
        dwflags: BCRYPT_FLAGS,
    ) -> NTSTATUS;

    #[link_name = "BCryptDecrypt"]
    fn bcrypt_decrypt_raw(
        hkey: BCRYPT_KEY_HANDLE,
        pbinput: *const u8,
        cbinput: u32,
        ppaddinginfo: *const core::ffi::c_void,
        pbiv: *mut u8,
        cbiv: u32,
        pboutput: *mut u8,
        cboutput: u32,
        pcbresult: *mut u32,
        dwflags: BCRYPT_FLAGS,
    ) -> NTSTATUS;
}

unsafe fn bcrypt_encrypt_in_place(
    hkey: BCRYPT_KEY_HANDLE,
    buffer: *mut u8,
    len: u32,
    info: *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    pcbresult: *mut u32,
    dwflags: BCRYPT_FLAGS,
) -> NTSTATUS {
    unsafe {
        bcrypt_encrypt_raw(
            hkey,
            buffer as *const u8,
            len,
            info as *const core::ffi::c_void,
            std::ptr::null_mut(),
            0,
            buffer,
            len,
            pcbresult,
            dwflags,
        )
    }
}

unsafe fn bcrypt_decrypt_in_place(
    hkey: BCRYPT_KEY_HANDLE,
    buffer: *mut u8,
    len: u32,
    info: *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    pcbresult: *mut u32,
    dwflags: BCRYPT_FLAGS,
) -> NTSTATUS {
    unsafe {
        bcrypt_decrypt_raw(
            hkey,
            buffer as *const u8,
            len,
            info as *const core::ffi::c_void,
            std::ptr::null_mut(),
            0,
            buffer,
            len,
            pcbresult,
            dwflags,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Algorithm {
    handle: BCRYPT_ALG_HANDLE,
    key_size: usize,
    is_aes: bool,
}

pub(crate) const AES_128_GCM: Algorithm = Algorithm {
    handle: BCRYPT_AES_GCM_ALG_HANDLE,
    key_size: 16,
    is_aes: true,
};

pub(crate) const AES_256_GCM: Algorithm = Algorithm {
    handle: BCRYPT_AES_GCM_ALG_HANDLE,
    key_size: 32,
    is_aes: true,
};

pub(crate) const CHACHA20_POLY1305: Algorithm = Algorithm {
    handle: BCRYPT_CHACHA20_POLY1305_ALG_HANDLE,
    key_size: 32,
    is_aes: false,
};

unsafe impl Send for Algorithm {}
unsafe impl Sync for Algorithm {}

pub(crate) struct AeadKey {
    handle: Owned<BCRYPT_KEY_HANDLE>,
}

unsafe impl Send for AeadKey {}
unsafe impl Sync for AeadKey {}

impl Algorithm {
    pub(crate) fn key_size(&self) -> usize {
        self.key_size
    }

    pub(crate) fn is_aes(&self) -> bool {
        self.is_aes
    }

    pub(crate) fn with_key(&self, key: &[u8]) -> Result<AeadKey, Error> {
        if key.len() != self.key_size {
            return Err(Error::General(format!(
                "Invalid key size for AEAD algorithm: {}",
                key.len()
            )));
        }

        let mut key_handle = Owned::default();
        unsafe {
            BCryptGenerateSymmetricKey(self.handle, &mut *key_handle, None, key, 0)
                .ok()
                .map_err(|e| Error::General(format!("AEAD key import error: {e}")))?;

            // if self.is_aes {
            //     let bcrypt_handle = BCRYPT_HANDLE(&mut *key_handle.0);
            //     BCryptSetProperty(
            //         bcrypt_handle,
            //         BCRYPT_CHAINING_MODE,
            //         &to_null_terminated_le_bytes(BCRYPT_CHAIN_MODE_GCM),
            //         0,
            //     )
            //     .ok()
            //     .map_err(|e| Error::General(format!("AEAD set chaining mode error: {e}")))?;
            // }
        }
        Ok(AeadKey { handle: key_handle })
    }
}

impl AeadKey {
    /// Encrypts data in place and returns the tag.
    pub(crate) fn seal(
        &self,
        nonce: [u8; NONCE_LEN], // Take ownership of nonce as it is modified in place.
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        let mut tag = [0u8; TAG_LEN];

        // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
        let mut info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: core::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: nonce.as_ptr().cast_mut(),
            cbNonce: nonce.len() as u32,
            pbTag: tag.as_mut_ptr(),
            cbTag: tag.len() as u32,
            pbAuthData: aad.as_ptr().cast_mut(),
            cbAuthData: aad.len() as u32,
            ..Default::default()
        };

        unsafe {
            // SAFETY: CNG supports in-place encryption, and the raw helper accepts one buffer pointer
            // so Rust does not materialize overlapping input and output slice references.
            let mut size = 0u32;
            let len = data.len().try_into().unwrap();

            bcrypt_encrypt_in_place(
                *self.handle,
                data.as_mut_ptr(),
                len,
                std::ptr::from_mut(&mut info),
                &mut size,
                BCRYPT_FLAGS::default(),
            )
            .ok()
            .map_err(|_| Error::EncryptError)?;
        }
        Ok(tag)
    }

    /// Decrypts in place, verifying the tag and returns the length of the plaintext.
    pub(crate) fn open(
        &self,
        nonce: [u8; NONCE_LEN], // Take ownership of nonce as it is modified in place.
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<usize, Error> {
        let payload_len = data.len();
        if payload_len < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let (ciphertext, tag) = data.split_at_mut(payload_len - TAG_LEN);

        // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
        let mut info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: core::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: nonce.as_ptr().cast_mut(),
            cbNonce: nonce.len() as u32,
            pbTag: tag.as_mut_ptr(),
            cbTag: tag.len() as u32,
            pbAuthData: aad.as_ptr().cast_mut(),
            cbAuthData: aad.len() as u32,
            ..Default::default()
        };

        let mut size = 0u32;

        unsafe {
            // SAFETY: CNG supports in-place decryption, and the raw helper accepts one buffer pointer
            // so Rust does not materialize overlapping input and output slice references.
            let len = ciphertext.len().try_into().unwrap();

            bcrypt_decrypt_in_place(
                *self.handle,
                ciphertext.as_mut_ptr(),
                len,
                std::ptr::from_mut(&mut info),
                &mut size,
                BCRYPT_FLAGS::default(),
            )
            .ok()
            .map_err(|_| Error::DecryptError)?;
        }
        size.try_into().map_err(|_| Error::DecryptError)
    }
}

#[cfg(test)]
mod test {

    use crate::aead::{Algorithm, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
    use rustls::Error;
    use wycheproof::{
        aead::{TestFlag, TestName},
        TestResult,
    };

    #[rstest::rstest]
    #[case::aes128gcm(AES_128_GCM, wycheproof::aead::TestName::AesGcm)]
    #[case::aes256gcm(AES_256_GCM, wycheproof::aead::TestName::AesGcm)]
    #[case::chacha20poly1305(CHACHA20_POLY1305, wycheproof::aead::TestName::ChaCha20Poly1305)]
    fn roundtrip(#[case] alg: Algorithm, #[case] test_name: TestName) {
        let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();
        let mut counter = 0;

        for group in test_set
            .test_groups
            .into_iter()
            .filter(|group| group.key_size == 8 * alg.key_size)
            .filter(|group| group.nonce_size == 96)
        {
            for test in group.tests {
                counter += 1;
                let mut iv_bytes = [0u8; 12];
                iv_bytes.copy_from_slice(&test.nonce[0..12]);

                let mut actual_ciphertext = test.pt.to_vec();

                let key = alg.with_key(&test.key).unwrap();
                let actual_tag = key
                    .seal(iv_bytes, &test.aad, &mut actual_ciphertext)
                    .unwrap();

                match &test.result {
                    TestResult::Invalid => {
                        if test.flags.contains(&TestFlag::ModifiedTag) {
                            assert_ne!(
                                actual_tag[..],
                                test.tag[..],
                                "Expected incorrect tag. Id {}: {}",
                                test.tc_id,
                                test.comment
                            );
                        }
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(
                            actual_ciphertext[..],
                            test.ct[..],
                            "Incorrect ciphertext on testcase {}: {}",
                            test.tc_id,
                            test.comment
                        );
                        assert_eq!(
                            actual_tag[..],
                            test.tag[..],
                            "Incorrect tag on testcase {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }

                let mut data = test.ct.to_vec();
                data.extend_from_slice(&test.tag);
                let res = key.open(iv_bytes, &test.aad, &mut data);

                match &test.result {
                    TestResult::Invalid => {
                        assert_eq!(res, Err(Error::DecryptError));
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(res, Ok(test.pt.len()));
                        assert_eq!(&data[..res.unwrap()], &test.pt[..]);
                    }
                }
            }
        }

        // Ensure we ran some tests.
        assert!(counter > 50);
    }
}
