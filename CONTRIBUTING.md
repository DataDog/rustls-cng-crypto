# Contributing to rustls-cng-crypto

Thanks for your interest in contributing to `rustls-cng-crypto`.

## Development setup

This crate implements a rustls crypto provider backed by Windows CNG. Full test coverage requires a Windows host because the implementation calls Windows cryptography APIs.

Install a stable Rust toolchain, then run:

```bash
cargo fmt -- --check
cargo test
```

On non-Windows hosts, use formatting and metadata checks locally, then rely on GitHub Actions for Windows validation.

## License inventory

This repository tracks third-party Rust dependencies in `LICENSE-3rdparty.csv`. The file is generated from `Cargo.lock` with Datadog's Rust license inventory tool.

After changing dependencies, run:

```bash
make sync-licenses
make check-licenses
```

Commit `Cargo.lock`, `LICENSE-3rdparty.csv`, and any required `license-tool.toml` override changes together. Do not hand-edit generated `LICENSE-3rdparty.csv` rows.

## Pull requests

Before opening a pull request:

1. Run `cargo fmt -- --check`.
2. Run `make check-licenses`.
3. Run `cargo test` on Windows or confirm that GitHub Actions will provide Windows test coverage.
4. Update documentation for user-visible changes.

## License

Unless explicitly stated otherwise, contributions are licensed under the MIT License. See `LICENSE` for the repository license and `LICENSE-3rdparty.csv` for third-party dependency notices.
