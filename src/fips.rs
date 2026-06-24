// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

use rustls::crypto::CryptoProvider;
use windows::Win32::Security::Cryptography::BCryptGetFipsAlgorithmMode;

use crate::{kx, KeyProvider, SecureRandom, ALL_CIPHER_SUITES, SUPPORTED_SIG_ALGS};

pub(crate) fn enabled() -> bool {
    let mut enabled = 0u8;
    unsafe {
        BCryptGetFipsAlgorithmMode(&mut enabled).ok().unwrap();
    }
    enabled != 0
}

/// Returns a CNG-based [`CryptoProvider`] using FIPS-approved cipher suites and key exchange groups.
///
/// To use rustls with this provider in FIPS mode:
///
/// 1. Enable FIPS mode for Windows. See Microsoft's
///    [FIPS 140 Validation](https://learn.microsoft.com/en-us/windows/security/security-foundations/certification/fips-140-validation)
///    documentation.
/// 2. Enable this crate's `fips` feature, or explicitly use [`crate::fips_provider()`]. The `fips`
///    feature changes [`crate::default_provider()`] to use FIPS-approved cipher suites and key
///    exchange groups.
/// 3. Specify `require_ems` when constructing [`rustls::ClientConfig`] or
///    [`rustls::ServerConfig`]. See the rustls
///    [FIPS manual](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html)
///    for rationale.
/// 4. Validate the FIPS status of your `ClientConfig` or `ServerConfig` at runtime. See the rustls
///    [FIPS status documentation](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html#3-validate-the-fips-status-of-your-clientconfigserverconfig-at-run-time).
///
/// Usage requires that Windows is running in FIPS mode, otherwise the provider will be empty.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES
            .iter()
            .filter(|cs| cs.fips())
            .cloned()
            .collect(),
        kx_groups: kx::default_kx_groups()
            .into_iter()
            .filter(|kx| kx.fips())
            .collect(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SecureRandom,
        key_provider: &KeyProvider,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn fips() {
        let provider = provider();
        assert_eq!(provider.fips(), enabled());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_provider_has_fips_cipher_suites() {
        let provider = provider();
        assert!(!provider.cipher_suites.is_empty());
        assert!(!provider.kx_groups.is_empty());
        assert!(provider.fips());
        assert!(provider.cipher_suites.iter().any(|cs| cs.tls13().is_some()));
        #[cfg(feature = "tls12")]
        assert!(provider.cipher_suites.iter().any(|cs| cs.tls13().is_none()));
        dbg!(provider);
    }
}
