<!--
Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.

This product includes software developed at Datadog (https://www.datadoghq.com/)
Copyright 2026 Datadog, Inc.
-->

# Open Source Review Notes

This file records repository-specific follow-ups for Datadog open-source review.

## Completed in repository files

- `LICENSE` is present and uses the MIT License.
- `NOTICE` is present with Datadog attribution.
- `LICENSE-3rdparty.csv` is present with `Component,Origin,License,Copyright` columns.
- `Cargo.lock` is tracked so the third-party license inventory is deterministic.
- `Makefile` includes `sync-licenses` and `check-licenses` targets backed by `dd-rust-license-tool`.
- GitHub pull request and issue templates are present.
- `CONTRIBUTING.md` and `SECURITY.md` are present.
- Comment-safe tracked files include the Datadog-required repository header.

## Verification performed locally

- `make check-licenses` passed.
- `cargo fmt -- --check` passed.
- `cargo check --all-targets` was attempted on macOS and failed in the `windows-future` dependency while checking Windows APIs on a non-Windows host.
- `cargo check --all-targets --target x86_64-pc-windows-msvc` was attempted on macOS and failed because the host lacks Windows SDK headers required by `aws-lc-sys` (`windows.h`).

Full compile and test validation should run in GitHub Actions on `windows-latest`.

## External follow-ups

- Trigger Datadog's self-service hard-coded credential scan and remediate any findings before requesting approval.
- Review GitHub branch protection against Datadog's secure repository guidance. At the time of this pass, the GitHub API reported that `main` was not protected.
- Confirm whether this repository will use Renovate. The Saluki-style license sync workflow in `.github/workflows/renovate-sync-licenses.yml` runs only for Renovate PRs with `renovate/` branches. If the repository remains on Dependabot, dependency PRs may require a human to run `make sync-licenses`.
- Ensure the `dd-octo-sts` policy in `.github/chainguard/self.renovate-sync-licenses.sts.yaml` is enabled for this repository before relying on automated signed write-back commits.
- Post in `#opensource` for review and approval. After approval, use the required Jira form for a GitHub Admin to make the repository public.
