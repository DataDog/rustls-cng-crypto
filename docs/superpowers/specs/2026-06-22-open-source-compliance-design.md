<!--
Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.

This product includes software developed at Datadog (https://www.datadoghq.com/)
Copyright 2026 Datadog, Inc.
-->

# Open Source Compliance Design

## Context

`DataDog/rustls-cng-crypto` is a non-linked fork of `tofay/rustls-cng-crypto`. The repository should be prepared for Datadog open-source review while preserving the upstream MIT licensing posture and commit history. The compliance source requirements are Datadog's open-source release checklist provided by Travis in this session.

## Goals

- Keep the repository under the MIT License, an approved Datadog open-source license.
- Add repository files required for Datadog open-source review: license inventory, NOTICE, contributing guide, GitHub issue and pull request templates, and security guidance.
- Add the Datadog-required file header where practical without breaking recognized license templates or generated/third-party license inventory semantics.
- Replace upstream GitHub references with `DataDog/rustls-cng-crypto` where the content is repository-specific.
- Add Saluki-style machinery to keep `LICENSE-3rdparty.csv` synchronized with Rust dependencies.
- Verify reachable GitHub repository settings and update safe metadata/settings where appropriate.

## Non-goals

- Change the crate's public API or crypto implementation.
- Switch from MIT to Apache-2.0.
- Publish the repository or bypass the required `#opensource` review and GitHub Admin process.
- Claim completion of Datadog's hard-coded credential scan unless a scan is actually run and its output is available.

## Licensing and headers

The repo will keep the MIT license. `LICENSE` should remain recognizable as an MIT license template. The Datadog attribution and default header text will be added to source, documentation, and configuration files using file-appropriate comment syntax. The header text will state:

```text
Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.

This product includes software developed at Datadog (https://www.datadoghq.com/)
Copyright 2026 Datadog, Inc.
```

For files where a header could interfere with machine parsing, recognition, or generated inventory semantics, the implementation will use the nearest safe equivalent or document the exception in the implementation notes.

## Third-party license inventory

The repository will follow the Saluki pattern:

- Commit `LICENSE-3rdparty.csv` with columns `Component,Origin,License,Copyright`.
- Commit `license-tool.toml` for `dd-rust-license-tool` overrides when crate metadata is incomplete or needs normalization.
- Track `Cargo.lock` so the license inventory is deterministic and CI can check it exactly.
- Add a small `Makefile` with pinned `dd-rust-license-tool` version plus:
  - `make sync-licenses` to regenerate `LICENSE-3rdparty.csv`.
  - `make check-licenses` to verify the committed CSV is up to date.

This mirrors Saluki's use of `dd-rust-license-tool`, while keeping this repo's machinery minimal because it is a single-crate Rust library.

## GitHub automation

The existing CI workflow will gain a license check job or step that runs `make check-licenses` on Linux. A Renovate license-sync workflow will be adapted from Saluki:

- run only on Renovate pull requests with `renovate/` branches,
- install the pinned `dd-rust-license-tool`,
- run `dd-rust-license-tool write`,
- commit `LICENSE-3rdparty.csv` only when it changes,
- use Datadog `dd-octo-sts` and `commit-headless` for scoped, signed write-back.

A repo-scoped `dd-octo-sts` policy file will be added under `.github/chainguard/` for the workflow. If the policy must be enabled by a GitHub or Chainguard administrator outside the repository, that follow-up will be reported.

## Documentation and templates

The implementation will add or update:

- `README.md` for a clear external project overview, Datadog repository links, testing notes, contribution link, security policy link, and license inventory link.
- `CONTRIBUTING.md` with development setup, tests, license inventory maintenance, and contribution expectations.
- `SECURITY.md` with Datadog vulnerability reporting guidance.
- `.github/PULL_REQUEST_TEMPLATE.md`.
- `.github/ISSUE_TEMPLATE/bug-report.yaml` and `.github/ISSUE_TEMPLATE/config.yml`.

`CODEOWNERS` will be added only if there is a known Datadog owner. Without an owner, it will be left out rather than adding a misleading placeholder.

## GitHub repository settings

Safe reachable settings will be updated when possible:

- description remains `A Windows CNG crypto provider for rustls`, matching the upstream repository,
- homepage remains empty unless a Datadog docs URL exists,
- topics remain empty unless explicitly requested,
- wiki/projects may be disabled for this library if the API permits and current usage is absent.

Branch protection, secret scanning, required status checks, and repository visibility changes may require admin review. The implementation will report current status and any blocked actions instead of assuming they are complete.

## Verification

Expected local verification:

- `cargo fmt -- --check`, if the local host can format the crate,
- `cargo generate-lockfile` and `make sync-licenses`,
- `make check-licenses`,
- `cargo test --no-run` or another feasible Rust check if macOS can evaluate the crate metadata without linking Windows-only APIs.

Expected remote/manual verification:

- GitHub Actions Windows CI for full tests,
- Datadog self-service hard-coded credential scan,
- review in `#opensource`,
- GitHub Admin public visibility workflow after approval.

## Risks and mitigations

- **Cargo.lock in a library repo:** Rust libraries often omit `Cargo.lock`, but deterministic third-party inventory and CI checking need a lockfile. The repo will track it intentionally and document that choice in `CONTRIBUTING.md`.
- **Headers in structured files:** Some formats tolerate comments and some do not. The implementation will avoid breaking parser-sensitive files and document any exceptions.
- **License metadata gaps:** `dd-rust-license-tool` may require overrides for crates with missing origins or custom license expressions. Overrides will be recorded in `license-tool.toml` rather than hand-editing generated CSV output.
- **Datadog automation dependencies:** The Renovate sync workflow depends on Datadog GitHub automation permissions. The workflow and policy can be committed now; activation or policy approval may remain an external follow-up.
