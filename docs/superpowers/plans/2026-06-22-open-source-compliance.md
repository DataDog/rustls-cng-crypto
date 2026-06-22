# Open Source Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare `DataDog/rustls-cng-crypto` for Datadog open-source review while preserving MIT licensing and adding Saluki-style license inventory automation.

**Architecture:** Keep product code unchanged. Add compliance documents, GitHub templates, deterministic Rust dependency inventory, and workflow automation around `dd-rust-license-tool`. Use file headers in comment-safe formats and avoid breaking recognized license templates.

**Tech Stack:** Rust/Cargo, GitHub Actions, `dd-rust-license-tool`, Make, YAML, Markdown.

---

## File structure

- Modify `Cargo.toml`: Datadog repository metadata.
- Create `Cargo.lock`: deterministic dependency graph for license inventory.
- Create `Makefile`: `sync-licenses`, `check-licenses`, and lightweight validation targets.
- Create `license-tool.toml`: license-tool overrides only when required by actual tool output.
- Create `LICENSE-3rdparty.csv`: generated third-party dependency inventory.
- Create `NOTICE`, `CONTRIBUTING.md`, `SECURITY.md`: open-source review docs.
- Modify `README.md`: Datadog links, compliance links, testing/contribution/security sections.
- Modify `.github/workflows/ci.yml`: add license check and Datadog headers.
- Create `.github/workflows/renovate-sync-licenses.yml`: Saluki-style Renovate license sync.
- Create `.github/chainguard/self.renovate-sync-licenses.sts.yaml`: scoped write policy for the workflow.
- Create `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/bug-report.yaml`, `.github/ISSUE_TEMPLATE/config.yml`: GitHub templates.
- Modify source and config files that accept comments to add Datadog-required headers.

---

### Task 1: Add compliance docs and templates

**Files:**
- Create: `NOTICE`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Create: `.github/ISSUE_TEMPLATE/bug-report.yaml`
- Create: `.github/ISSUE_TEMPLATE/config.yml`
- Modify: `README.md`
- Modify: `Cargo.toml`

- [ ] **Step 1: Update crate metadata**

Set `homepage` and `repository` in `Cargo.toml` to `https://github.com/DataDog/rustls-cng-crypto`. Keep `license = "MIT"` and preserve upstream author metadata.

- [ ] **Step 2: Add NOTICE**

Create `NOTICE` with:

```text
Datadog rustls-cng-crypto
Copyright 2026-Present Datadog, Inc.
This product includes software developed at Datadog (https://www.datadoghq.com/).
```

- [ ] **Step 3: Add contribution/security docs and GitHub templates**

Add docs that explain development, testing, license inventory maintenance, security reporting, and PR/issue expectations without changing product behavior.

- [ ] **Step 4: Update README**

Keep the existing project overview, update GitHub badge links to `DataDog/rustls-cng-crypto`, add sections for Datadog fork status, contributing, security, license, third-party licenses, and testing.

- [ ] **Step 5: Commit**

Run:

```bash
git add Cargo.toml README.md NOTICE CONTRIBUTING.md SECURITY.md .github/PULL_REQUEST_TEMPLATE.md .github/ISSUE_TEMPLATE
git commit -m "docs: add open source compliance documentation"
```

Expected: commit succeeds.

---

### Task 2: Add Saluki-style license inventory machinery

**Files:**
- Create: `Cargo.lock`
- Create: `Makefile`
- Create: `license-tool.toml`
- Create: `LICENSE-3rdparty.csv`
- Modify: `.gitignore`
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/renovate-sync-licenses.yml`
- Create: `.github/chainguard/self.renovate-sync-licenses.sts.yaml`

- [ ] **Step 1: Track Cargo.lock**

Remove `Cargo.lock` from `.gitignore`, then run:

```bash
cargo generate-lockfile
```

Expected: `Cargo.lock` is created.

- [ ] **Step 2: Add Makefile**

Create a small `Makefile` with pinned `CARGO_TOOL_VERSION_dd-rust-license-tool ?= 1.0.6`, `sync-licenses`, `check-licenses`, `fmt`, `clippy`, and `test` targets.

- [ ] **Step 3: Generate license inventory**

Run:

```bash
cargo install dd-rust-license-tool@1.0.6 || true
make sync-licenses
```

If the tool reports missing/ambiguous metadata, add only the required entries to `license-tool.toml`, rerun `make sync-licenses`, and keep generated `LICENSE-3rdparty.csv` unchanged by hand.

- [ ] **Step 4: Add CI license check**

Add a Linux `license` job to `.github/workflows/ci.yml` that checks out the repo, installs stable Rust, caches Cargo, and runs `make check-licenses`.

- [ ] **Step 5: Add Renovate sync workflow and STS policy**

Adapt Saluki's workflow for `DataDog/rustls-cng-crypto`, including `dd-octo-sts-action`, `commit-headless`, and `.github/chainguard/self.renovate-sync-licenses.sts.yaml` with the repo-specific subject and workflow ref.

- [ ] **Step 6: Commit**

Run:

```bash
git add .gitignore Cargo.lock Makefile license-tool.toml LICENSE-3rdparty.csv .github/workflows/ci.yml .github/workflows/renovate-sync-licenses.yml .github/chainguard/self.renovate-sync-licenses.sts.yaml
git commit -m "ci: add third-party license inventory checks"
```

Expected: commit succeeds.

---

### Task 3: Add Datadog-required headers

**Files:**
- Modify comment-safe tracked files including `.rs`, `.toml`, `.yml`, `.yaml`, `.md`, `Makefile`, `.gitignore`.
- Do not add a header to `LICENSE` or generated `LICENSE-3rdparty.csv`.

- [ ] **Step 1: Add headers by syntax**

Use these header forms:

Rust:

```rust
// Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.
```

Markdown:

```markdown
<!--
Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.

This product includes software developed at Datadog (https://www.datadoghq.com/)
Copyright 2026 Datadog, Inc.
-->
```

YAML/Make/gitignore/TOML:

```text
# Unless explicitly stated otherwise all files in this repository are licensed under the MIT License.
#
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026 Datadog, Inc.
```

- [ ] **Step 2: Keep generated and license template files parse-safe**

Leave `LICENSE` unchanged as a recognized MIT template. Leave `LICENSE-3rdparty.csv` generated-only with no header.

- [ ] **Step 3: Commit**

Run:

```bash
git add .
git commit -m "chore: add Datadog source headers"
```

Expected: commit succeeds.

---

### Task 4: Verify and update reachable GitHub settings

**Files:**
- No required file changes unless verification reveals a doc correction.

- [ ] **Step 1: Run local verification**

Run:

```bash
make check-licenses
cargo fmt -- --check
cargo check --all-targets
```

Expected: license and formatting checks pass. If `cargo check` fails because Windows APIs cannot be checked on macOS, capture the concise failure and report that GitHub Actions Windows CI must validate it.

- [ ] **Step 2: Check secrets tooling availability**

Run:

```bash
command -v gitleaks || command -v detect-secrets || true
```

If a tool exists, run it with a safe no-output-on-success mode. If no tool exists, report that Datadog self-service credential scan remains required.

- [ ] **Step 3: Update safe GitHub settings**

Using a token that can see `DataDog/rustls-cng-crypto`, ensure description is `A Windows CNG crypto provider for rustls`, homepage is empty, topics are empty, and disable wiki/projects if permitted.

- [ ] **Step 4: Commit any verification-driven doc fixes**

If verification required doc updates, commit them with:

```bash
git add <changed-doc-files>
git commit -m "docs: record open source review follow-ups"
```

Expected: commit succeeds only if files changed.
