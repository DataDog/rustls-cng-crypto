// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

use crate::aead::{self, AeadKey, TAG_LEN};
use crate::hash::{SHA256, SHA384};
use crate::prf::Prf;
use crate::signer::RSA_SCHEMES;
use rustls::crypto::cipher::{
    make_tls12_aad, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::crypto::KeyExchangeAlgorithm;
use rustls::{
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, Error, SignatureScheme,
    SupportedCipherSuite, Tls12CipherSuite,
};

const GCM_EXPLICIT_NONCE_LENGTH: usize = 8;
const GCM_IMPLICIT_NONCE_LENGTH: usize = 4;
const MAX_FRAGMENT_LEN: usize = 16 * 1024;

static ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &aead::CHACHA20_POLY1305,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &aead::CHACHA20_POLY1305,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &aead::AES_128_GCM,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &aead::AES_256_GCM,
        prf_provider: &Prf(SHA384),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &aead::AES_128_GCM,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &aead::AES_256_GCM,
        prf_provider: &Prf(SHA384),
    });

struct AesGcmDecrypter {
    key: AeadKey,
    implicit_iv: [u8; GCM_IMPLICIT_NONCE_LENGTH],
}

struct AesGcmEncrypter {
    key: AeadKey,
    full_iv: Iv,
}

pub(crate) struct ChaCha20Poly1305Crypter {
    key: AeadKey,
    iv: Iv,
}

impl Tls12AeadAlgorithm for aead::Algorithm {
    fn encrypter(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        if self.is_aes() {
            let mut full_iv = [0u8; NONCE_LEN];
            full_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
            full_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(extra);
            Box::new(AesGcmEncrypter {
                key: self.with_key(key.as_ref()).unwrap(),
                full_iv: Iv::new(full_iv),
            })
        } else {
            Box::new(ChaCha20Poly1305Crypter {
                key: self.with_key(key.as_ref()).unwrap(),
                iv: Iv::copy(iv),
            })
        }
    }

    fn decrypter(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: &[u8],
    ) -> Box<dyn MessageDecrypter> {
        if self.is_aes() {
            let mut implicit_iv = [0u8; GCM_IMPLICIT_NONCE_LENGTH];
            implicit_iv.copy_from_slice(iv);
            Box::new(AesGcmDecrypter {
                key: self.with_key(key.as_ref()).unwrap(),
                implicit_iv,
            })
        } else {
            Box::new(ChaCha20Poly1305Crypter {
                key: self.with_key(key.as_ref()).unwrap(),
                iv: Iv::copy(iv),
            })
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        if self.is_aes() {
            KeyBlockShape {
                enc_key_len: self.key_size(),
                fixed_iv_len: GCM_IMPLICIT_NONCE_LENGTH,
                explicit_nonce_len: GCM_EXPLICIT_NONCE_LENGTH,
            }
        } else {
            KeyBlockShape {
                enc_key_len: self.key_size(),
                fixed_iv_len: NONCE_LEN,
                explicit_nonce_len: 0,
            }
        }
    }

    fn extract_keys(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match (self.is_aes(), self.key_size()) {
            (true, 16) => {
                let mut gcm_iv = [0; NONCE_LEN];
                gcm_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
                gcm_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(explicit);
                Ok(ConnectionTrafficSecrets::Aes128Gcm {
                    key,
                    iv: Iv::new(gcm_iv),
                })
            }
            (true, 32) => {
                let mut gcm_iv = [0; NONCE_LEN];
                gcm_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
                gcm_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(explicit);
                Ok(ConnectionTrafficSecrets::Aes256Gcm {
                    key,
                    iv: Iv::new(gcm_iv),
                })
            }
            (false, 32) => Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
                key,
                iv: Iv::new(iv[..].try_into().map_err(|_| UnsupportedOperationError)?),
            }),
            _ => Err(UnsupportedOperationError),
        }
    }

    fn fips(&self) -> bool {
        self.is_aes() && crate::fips::enabled()
    }
}

impl MessageEncrypter for AesGcmEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let msg_len = msg.payload.len();
        let total_len = self.encrypted_payload_len(msg_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = Nonce::new(&self.full_iv, seq);
        payload.extend_from_slice(&nonce.0[GCM_IMPLICIT_NONCE_LENGTH..]);
        payload.extend_from_chunks(&msg.payload);

        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg_len);

        let tag = self.key.seal(
            nonce.0,
            &aad,
            &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LENGTH..GCM_EXPLICIT_NONCE_LENGTH + msg_len],
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        GCM_EXPLICIT_NONCE_LENGTH + payload_len + TAG_LEN
    }
}

impl MessageDecrypter for AesGcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let payload_len = payload.len();
        if payload_len < TAG_LEN + GCM_EXPLICIT_NONCE_LENGTH {
            return Err(Error::DecryptError);
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(&self.implicit_iv);
        nonce[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LENGTH]);

        let aad = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload_len - TAG_LEN - GCM_EXPLICIT_NONCE_LENGTH,
        );

        let plaintext_len = self.key.open(
            nonce,
            &aad,
            &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LENGTH..],
        )?;
        if plaintext_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        // Remove the explicit nonce from the front of the buffer, as it's not part of the plaintext.
        payload.copy_within(
            GCM_EXPLICIT_NONCE_LENGTH..(GCM_EXPLICIT_NONCE_LENGTH + plaintext_len),
            0,
        );
        payload.truncate(plaintext_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for ChaCha20Poly1305Crypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_chunks(&msg.payload);

        let tag = self.key.seal(nonce.0, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

impl MessageDecrypter for ChaCha20Poly1305Crypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let payload_len = payload.len();
        if payload_len < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let message_len = payload_len - TAG_LEN;

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, message_len);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&payload[message_len..]);

        let plaintext_len = self.key.open(nonce.0, &aad, payload)?;
        if plaintext_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.truncate(plaintext_len);
        Ok(msg.into_plain_message())
    }
}

#[cfg(test)]
mod test {
    use rustls::crypto::cipher::{InboundOpaqueMessage, OutboundChunks, OutboundPlainMessage};
    use rustls::{ContentType, Error, ProtocolVersion, SupportedCipherSuite};

    use super::{
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };

    #[test]
    fn tls12_aes256_gcm_suites_use_32_byte_keys() {
        for suite in [
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ] {
            let SupportedCipherSuite::Tls12(suite) = suite else {
                panic!("expected a TLS 1.2 cipher suite");
            };

            assert_eq!(
                suite.aead_alg.key_block_shape().enc_key_len,
                32,
                "{:?} should derive 32-byte AES-256-GCM keys",
                suite.common.suite
            );
        }
    }

    #[test]
    fn tls12_aead_decrypt_rejects_oversized_plaintext() {
        for suite in [
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ] {
            let SupportedCipherSuite::Tls12(suite) = suite else {
                panic!("expected a TLS 1.2 cipher suite");
            };

            let shape = suite.aead_alg.key_block_shape();
            let key_bytes = [0x42; 32];
            let iv = vec![0x5a; shape.fixed_iv_len];
            let explicit = vec![0xa5; shape.explicit_nonce_len];
            let plaintext = vec![0x3c; MAX_FRAGMENT_LEN + 1];
            let seq = 0;

            let mut encrypter = suite.aead_alg.encrypter(key_bytes.into(), &iv, &explicit);
            let plain_message = OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::from(plaintext.as_slice()),
            };
            let mut ciphertext = encrypter.encrypt(plain_message, seq).unwrap();

            let mut decrypter = suite.aead_alg.decrypter(key_bytes.into(), &iv);
            let opaque_message = InboundOpaqueMessage::new(
                ciphertext.typ,
                ciphertext.version,
                ciphertext.payload.as_mut(),
            );
            let err = decrypter.decrypt(opaque_message, seq).unwrap_err();
            assert_eq!(
                err,
                Error::PeerSentOversizedRecord,
                "{:?} should reject plaintext longer than the TLS record limit",
                suite.common.suite
            );
        }
    }
}
