// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

use crate::aead::{self, AeadKey};
use crate::hash::{SHA256, SHA384};
use crate::hkdf::Hkdf;
use crate::quic;
use rustls::crypto::cipher::{
    make_tls13_aad, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::CipherSuiteCommon;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, Error, SupportedCipherSuite, Tls13CipherSuite,
};

/// The TLS1.3 ciphersuite `TLS_CHACHA20_POLY1305_SHA256`
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &Hkdf::new(SHA256),
        aead_alg: &aead::CHACHA20_POLY1305,
        quic: None,
        // quic: Some(&quic::KeyBuilder {
        //     packet_algo: aead::CHACHA20_POLY1305,
        //     header_algo: quic::HEADER_ALG_CHACHA20,
        //     // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        //     confidentiality_limit: u64::MAX,
        //     // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        //     integrity_limit: 1 << 36,
        // }),
    });

/// The TLS1.3 ciphersuite `TLS_AES_256_GCM_SHA384`
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &Hkdf::new(SHA384),
        aead_alg: &aead::AES_256_GCM,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::AES_256_GCM,
            header_algo: quic::HEADER_ALG_AES,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

/// The TLS1.3 ciphersuite `TLS_AES_128_GCM_SHA256`
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &Hkdf::new(SHA256),
        aead_alg: &aead::AES_128_GCM,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::AES_128_GCM,
            header_algo: quic::HEADER_ALG_AES,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

struct Tls13Crypter {
    key: AeadKey,
    iv: Iv,
}

impl Tls13AeadAlgorithm for aead::Algorithm {
    fn encrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let key = self.with_key(key.as_ref()).unwrap();
        Box::new(Tls13Crypter { key, iv })
    }

    fn decrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let key = self.with_key(key.as_ref()).unwrap();
        Box::new(Tls13Crypter { key, iv })
    }

    fn key_len(&self) -> usize {
        self.key_size()
    }

    fn extract_keys(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match (self.key_size(), self.is_aes()) {
            (16, true) => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            (32, true) => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            (32, false) => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
            _ => return Err(UnsupportedOperationError),
        })
    }

    fn fips(&self) -> bool {
        self.is_aes() && crate::fips::enabled()
    }
}

impl MessageEncrypter for Tls13Crypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let aad = make_tls13_aad(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = self
            .key
            .seal(Nonce::new(&self.iv, seq).0, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            rustls::ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + aead::TAG_LEN
    }
}

impl MessageDecrypter for Tls13Crypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let aad = make_tls13_aad(payload.len());
        let plaintext_len = self
            .key
            .open(Nonce::new(&self.iv, seq).0, &aad, payload.as_mut())?;
        // Remove the tag from the end of the payload.
        payload.truncate(plaintext_len);
        msg.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{
        ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    };

    use super::*;

    static TLS13_AES_256_GCM_SHA384_HKDF_FALLBACK: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
                hash_provider: &SHA384,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &Hkdf::fallback(SHA384),
            aead_alg: &aead::AES_256_GCM,
            quic: None,
        });

    static TLS13_AES_128_GCM_SHA256_HKDF_FALLBACK: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                hash_provider: &SHA256,
                confidentiality_limit: 1 << 23,
            },
            hkdf_provider: &Hkdf::fallback(SHA256),
            aead_alg: &aead::AES_128_GCM,
            quic: None,
        });

    /// Returns a CA certificate, and a `localhost` server certificate and key that the CA issues.
    fn test_pki() -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.is_ca = rcgen::IsCa::NoCa;
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        (
            ca_cert.into(),
            server_cert.into(),
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
    }

    /// Moves all pending TLS records from one connection to the other.
    fn transfer(from: &mut Connection, to: &mut Connection) {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).unwrap();
        }

        let mut records = &buf[..];
        while !records.is_empty() {
            to.read_tls(&mut records).unwrap();
            to.process_new_packets().unwrap();
        }
    }

    #[test]
    fn hkdf_fallback_cipher_suites_are_not_fips() {
        // Rustls reports a TLS 1.3 cipher suite as FIPS only when its HKDF is, so a FIPS provider
        // never keeps a cipher suite that uses the fallback.
        assert!(!TLS13_AES_256_GCM_SHA384_HKDF_FALLBACK.fips());
        assert!(!TLS13_AES_128_GCM_SHA256_HKDF_FALLBACK.fips());
    }

    /// Completes a TLS 1.3 handshake in memory, with one peer on the HMAC HKDF fallback and the
    /// other on the cipher suite from the default provider. On hosts with the CNG HKDF algorithm,
    /// this checks the fallback against it.
    #[rstest::rstest]
    #[case::client_fallback_aes_256_gcm_sha384(
        TLS13_AES_256_GCM_SHA384_HKDF_FALLBACK,
        TLS13_AES_256_GCM_SHA384
    )]
    #[case::client_fallback_aes_128_gcm_sha256(
        TLS13_AES_128_GCM_SHA256_HKDF_FALLBACK,
        TLS13_AES_128_GCM_SHA256
    )]
    #[case::server_fallback_aes_256_gcm_sha384(
        TLS13_AES_256_GCM_SHA384,
        TLS13_AES_256_GCM_SHA384_HKDF_FALLBACK
    )]
    #[case::server_fallback_aes_128_gcm_sha256(
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_128_GCM_SHA256_HKDF_FALLBACK
    )]
    fn tls13_handshake_with_hkdf_fallback(
        #[case] client_suite: SupportedCipherSuite,
        #[case] server_suite: SupportedCipherSuite,
    ) {
        let (ca_cert, server_cert, server_key) = test_pki();
        let kx_groups = vec![crate::kx_group::SECP256R1];

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert).unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(crate::custom_provider(
            vec![client_suite],
            kx_groups.clone(),
        )))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

        let server_config = ServerConfig::builder_with_provider(Arc::new(crate::custom_provider(
            vec![server_suite],
            kx_groups,
        )))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], server_key)
        .unwrap();

        let server_name = "localhost".try_into().unwrap();
        let mut client: Connection = ClientConnection::new(Arc::new(client_config), server_name)
            .unwrap()
            .into();
        let mut server: Connection = ServerConnection::new(Arc::new(server_config))
            .unwrap()
            .into();

        while client.is_handshaking() || server.is_handshaking() {
            transfer(&mut client, &mut server);
            transfer(&mut server, &mut client);
        }

        assert_eq!(
            client.negotiated_cipher_suite().map(|cs| cs.suite()),
            Some(client_suite.suite())
        );

        // Application data uses traffic keys that both peers derive with HKDF.
        client.writer().write_all(b"ping").unwrap();
        transfer(&mut client, &mut server);
        let mut received = [0u8; 4];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"ping");

        server.writer().write_all(b"pong").unwrap();
        transfer(&mut server, &mut client);
        client.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"pong");

        // Exported keying material also uses HKDF, so both peers must agree on it.
        let client_ekm = client
            .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"context"))
            .unwrap();
        let server_ekm = server
            .export_keying_material([0u8; 32], b"EXPORTER-test", Some(b"context"))
            .unwrap();
        assert_eq!(client_ekm, server_ekm);
    }
}
