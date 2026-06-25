// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        panic!(
            "rustls-cng-crypto uses Windows CNG APIs and only builds for Windows targets; \
             use --target x86_64-pc-windows-msvc when checking from non-Windows hosts"
        );
    }
}
