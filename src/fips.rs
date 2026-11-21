// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

use rustls::crypto::CryptoProvider;
use windows::Win32::Security::Cryptography::BCryptGetFipsAlgorithmMode;

use crate::{default_cipher_suites, kx, KeyProvider, SecureRandom, SUPPORTED_SIG_ALGS};

pub(crate) fn enabled() -> bool {
    let mut enabled = 0u8;
    let query_succeeded = unsafe { BCryptGetFipsAlgorithmMode(&mut enabled).ok().is_ok() };
    enabled_from_query_result(query_succeeded, enabled)
}

fn enabled_from_query_result(query_succeeded: bool, enabled: u8) -> bool {
    query_succeeded && enabled != 0
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
///
/// On hosts without a CNG HKDF algorithm, such as Windows Server 2016, the TLS 1.3 cipher suites
/// use an HKDF composed from CNG HMAC. These cipher suites do not report FIPS status, so this
/// provider leaves them out. The TLS 1.2 cipher suites remain. Without the `tls12` feature, the
/// provider then has no cipher suites, and building a TLS configuration from it fails.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: default_cipher_suites()
            .into_iter()
            .filter(|cs| cs.fips())
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
    fn fips_query_result_is_enabled_only_when_query_succeeds_and_windows_reports_enabled() {
        assert!(enabled_from_query_result(true, 1));
        assert!(!enabled_from_query_result(true, 0));
        assert!(!enabled_from_query_result(false, 1));
    }

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
