// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

use rustls::CipherSuite;
use rustls_cng_crypto::{custom_provider, kx_group};

#[test]
fn tls13_chacha20_poly1305_sha256_is_available_for_custom_providers() {
    let provider = custom_provider(
        vec![rustls_cng_crypto::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
        vec![kx_group::SECP256R1],
    );

    assert_eq!(provider.cipher_suites.len(), 1);
    assert_eq!(
        provider.cipher_suites[0].suite(),
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    );
}
