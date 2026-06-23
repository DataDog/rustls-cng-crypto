// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

//! Algorithm provider initialization.
use once_cell::sync::OnceCell;
use rustls::Error;
#[cfg(feature = "tls12")]
use windows::Win32::Security::Cryptography::BCRYPT_TLS1_2_KDF_ALGORITHM;
use windows::Win32::Security::Cryptography::{
    BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_ECC_CURVE_25519, BCRYPT_ECC_CURVE_NAME,
    BCRYPT_ECDH_ALGORITHM, BCRYPT_HANDLE,
};
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS},
};

struct Handle(BCRYPT_ALG_HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

pub(crate) fn ecdh_x25519() -> Result<BCRYPT_ALG_HANDLE, Error> {
    static ALG_HANDLE: OnceCell<Option<Handle>> = OnceCell::new();
    ALG_HANDLE
        .get_or_init(|| {
            load_algorithm(
                BCRYPT_ECDH_ALGORITHM,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
                Some((BCRYPT_ECC_CURVE_NAME, BCRYPT_ECC_CURVE_25519)),
            )
            .ok()
            .map(Handle)
        })
        .as_ref()
        .map(|handle| handle.0)
        .ok_or_else(|| Error::General("CNG X25519 algorithm provider unavailable".into()))
}

#[cfg(feature = "tls12")]
pub(crate) fn tls12_kdf() -> BCRYPT_ALG_HANDLE {
    static ALG_HANDLE: OnceCell<Handle> = OnceCell::new();
    ALG_HANDLE
        .get_or_init(|| {
            Handle(
                load_algorithm(
                    BCRYPT_TLS1_2_KDF_ALGORITHM,
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
                    None,
                )
                .unwrap(),
            )
        })
        .0
}

/// Load an algorithm provider with specified flags, and optional property.
fn load_algorithm(
    id: PCWSTR,
    flags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    property: Option<(PCWSTR, PCWSTR)>,
) -> Result<BCRYPT_ALG_HANDLE, Error> {
    let mut alg_handle = BCRYPT_ALG_HANDLE::default();
    unsafe {
        BCryptOpenAlgorithmProvider(&mut alg_handle, id, None, flags)
            .ok()
            .map_err(|e| Error::General(format!("BCryptOpenAlgorithmProvider error: {e}")))?;
        if let Some((property, value)) = property {
            let bcrypt_handle = BCRYPT_HANDLE(alg_handle.0);
            BCryptSetProperty(
                bcrypt_handle,
                property,
                &to_null_terminated_le_bytes(value),
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("BCryptSetProperty error: {e}")))?;
        }
    }
    Ok(alg_handle)
}

fn to_null_terminated_le_bytes(str: PCWSTR) -> Vec<u8> {
    unsafe {
        str.as_wide()
            .iter()
            .copied()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}
