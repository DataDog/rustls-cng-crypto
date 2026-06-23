# rustls-cng-crypto

A [rustls Crypto Provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html) for Windows that uses [CNG](https://learn.microsoft.com/en-us/windows/win32/seccng/about-cng) for cryptographic operations.

This repository is a Datadog-maintained fork of [`tofay/rustls-cng-crypto`](https://github.com/tofay/rustls-cng-crypto).

See the [documentation](https://docs.rs/rustls-cng-crypto) for supported cipher suites and algorithms, along with instructions for running in FIPS mode.

[![crates.io](https://img.shields.io/crates/v/rustls-cng-crypto?style=flat-square&logo=rust)](https://crates.io/crates/rustls-cng-crypto)
[![Build Status](https://github.com/DataDog/rustls-cng-crypto/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DataDog/rustls-cng-crypto/actions/workflows/ci.yml?query=branch%3Amain)
[![Documentation](https://docs.rs/rustls-cng-crypto/badge.svg)](https://docs.rs/rustls-cng-crypto/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Testing

This project tests the crypto provider operations using test vectors from [Project Wycheproof](https://github.com/C2SP/wycheproof) where applicable.

Full test coverage requires Windows because the provider calls Windows CNG APIs:

```bash
cargo test
```

The default test suite is hermetic. The crates.io interoperability test is ignored by default because it requires live network access; run it explicitly when needed:

```bash
cargo test test_to_internet -- --ignored
```

This crate only builds for Windows targets. From non-Windows hosts, run check and documentation workflows with an explicit Windows target:

```bash
cargo check --target x86_64-pc-windows-msvc
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --target x86_64-pc-windows-msvc
```

Run formatting checks before submitting changes:

```bash
cargo fmt -- --check
```

## Third-party licenses

Third-party Rust dependencies are tracked in [`LICENSE-3rdparty.csv`](LICENSE-3rdparty.csv). The file is generated from `Cargo.lock` with Datadog's Rust license inventory tool.

After changing dependencies, run:

```bash
make sync-licenses
make check-licenses
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development and pull request guidance.

## Security

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting instructions.

## License

This repository is licensed under the [MIT License](LICENSE). Unless explicitly stated otherwise, files in this repository are licensed under the MIT License.
