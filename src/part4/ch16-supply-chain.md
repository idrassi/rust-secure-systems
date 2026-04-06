# Chapter 16 — Supply Chain Security

> *"Your code is only as secure as your weakest dependency."*

Modern software is built on layers of dependencies, each of which represents trust. A single compromised dependency can introduce a backdoor into every application that uses it. The Rust ecosystem, centered around crates.io, has experienced supply chain attacks including typo-squatting, dependency confusion, and maintainer account compromise.

This chapter covers how to protect your Rust project from supply chain attacks—from dependency selection to build reproducibility.

## 16.1 The Threat Model

### 16.1.1 Attack Vectors

| Attack Vector | Example | Impact |
|---------------|---------|--------|
| **Malicious crate** | Attacker publishes crate with backdoor | Remote code execution |
| **Typosquatting** | `ructls` instead of `rustls` | Backdoored dependency |
| **Dependency confusion** | Internal crate name matches public crate | Code from public source runs |
| **Account compromise** | Attacker gains publish access | Malicious version pushed |
| **Protestware** | Maintainer intentionally sabotages | Data destruction, disruption |
| **Build system compromise** | Tampered CI/CD pipeline | Backdoored binaries |
| **Registry compromise** | crates.io or npm attacked | All packages affected |

### 16.1.2 Real-World Incidents

- **event-stream (npm, 2018)**: Attacker became maintainer of popular package and added cryptocurrency-stealing code.
- **ua-parser-js (npm, 2021)**: Maintainer's account compromised, malicious versions published.
- **crates.io typosquatting campaigns**: Malicious crates with lookalike names have been published to steal data or execute code during builds.
- **colors.js/faker.js (npm, 2022)**: Maintainer deliberately broke their own packages.

## 16.2 Dependency Selection Criteria

### 16.2.1 Evaluating Crate Trustworthiness

Before adding a dependency, evaluate:

**Code Quality Signals**:
- [ ] Does the crate have comprehensive tests?
- [ ] Is there CI/CD with security checks?
- [ ] Is there a security policy (`SECURITY.md`)?
- [ ] Are dependencies minimal? (Fewer transitive dependencies = smaller attack surface)

**Maintenance Signals**:
- [ ] Is the crate actively maintained? (Recent commits, responsive issues)
- [ ] How many maintainers have publish access?
- [ ] How long has the crate existed?
- [ ] Are there known security advisories?

**Community Signals**:
- [ ] How many GitHub stars / crates.io downloads?
- [ ] Is it recommended by authoritative sources?
- [ ] Has it been audited by a third party?

**Code Safety**:
- [ ] How much `unsafe` code does it contain? (`cargo geiger`)
- [ ] Does it use FFI to C libraries? (Adds C attack surface)
- [ ] Does it use build scripts (`build.rs`)? (Can execute arbitrary code at build time)
- [ ] Does it ship procedural macros? (Also executes code at compile time)

### 16.2.2 Prefer the Standard Library and Core Ecosystem

```rust
// PREFER: Standard library
use std::sync::Mutex;

// OVER: Third-party alternatives (unless they provide clear benefits)
// use some_custom_mutex::Mutex;
```

The standard library and closely-governed crates (like those under the `rust-lang` organization) have the highest trust level.

### 16.2.3 Minimal Dependencies

Every dependency is a liability. Audit regularly:

```bash
cargo tree --duplicates     # Find duplicate versions
cargo tree --depth 1        # See direct dependencies
cargo tree --invert ring    # See who depends on a specific crate
```

## 16.3 Pinning and Locking Dependencies

### 16.3.1 Commit `Cargo.lock`

For binaries, always commit `Cargo.lock`:

```bash
git add Cargo.lock
git commit -m "Lock dependency versions for reproducible builds"
```

🔒 **Security impact**: Ensures every build uses the exact same dependency versions. Without `Cargo.lock`, a `cargo build` might pull a newer (potentially compromised) version.

### 16.3.2 Restrict Version Ranges

```toml
# BROAD: allows any compatible 1.x version
[dependencies]
serde = "1"

# TIGHTER: sets a minimum compatible version, but still allows newer 1.x releases
[dependencies]
serde = "1.0.195"

# EXACT: pin one precise version in Cargo.toml (use sparingly)
[dependencies]
serde = "=1.0.195"

# BEST for applications: commit Cargo.lock and review updates deliberately
```

⚠️ **Balance**: Cargo version requirements are ranges unless you use `=`. For most binaries, keep exact reproducibility in `Cargo.lock` and update it deliberately rather than hard-pinning every dependency in `Cargo.toml`.

## 16.4 `cargo-deny` for Policy Enforcement

```bash
cargo install cargo-deny --version 0.19.0 --locked
cargo deny init
cargo deny check
```

### 16.4.1 License Compliance

```toml
# deny.toml
[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
    "Unlicense",
    "Zlib",
]
unlicensed = "deny"
# Reject copyleft licenses in proprietary software
deny = ["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"]
```

### 16.4.2 Ban Dangerous Crates

```toml
# deny.toml
[bans]
# Ban crates with known issues
deny = [
    { name = "openssl", wrappers = ["my-openssl-wrapper"] },  # Only allow via wrapper
    { name = "chrono", version = "<0.4.20" },                 # Old versions have soundness bugs
]

# Reject wildcard dependencies
wildcards = "deny"

# Warn on multiple versions of the same crate
multiple-versions = "warn"
```

### 16.4.3 Source Restrictions

```toml
# deny.toml
[sources]
unknown-registry = "deny"    # Only crates.io
unknown-git = "deny"         # No git dependencies without explicit allow
allow-registry = ["sparse+https://index.crates.io/"]
allow-git = ["https://github.com/your-org/your-private-crate"]

# Add private registries or additional approved git sources explicitly as needed.

[bans.build]
# Start strict, then allow only reviewed compile-time crates that genuinely
# need build scripts or proc-macro-adjacent tooling.
allow-build-scripts = ["ring", "aws-lc-sys"]
executables = "deny"
interpreted = "warn"
enable-builtin-globs = true
include-dependencies = true
```

This does **not** sandbox malicious Rust code in a reviewed build script. What it does give you is visibility and policy enforcement around compile-time crates and script-like artifacts, which is still useful when you are inventorying build-time risk. An empty allow-list is a good audit starting point when you want the build to fail closed and show you every compile-time dependency, but it is not a realistic copy-paste baseline for most working Rust workspaces.

### 16.4.4 `cargo-supply-chain` for Publisher Visibility

`cargo-deny` tells you whether a dependency violates policy. `cargo-supply-chain` answers a different question: *who* are you implicitly trusting across the full dependency graph?

```bash
cargo install cargo-supply-chain --locked
cargo supply-chain publishers
cargo supply-chain crates
```

Use it to spot one-off publishers, surprising maintainer concentration, or dependency subtrees published by accounts you have never reviewed. That context is especially useful when assessing typosquatting and maintainer-account compromise risks, and it complements the deeper per-version review flows from `cargo-vet`.

## 16.5 Build Reproducibility

### 16.5.1 Reproducible Builds

A reproducible build produces identical output given the same source code, regardless of the build environment. This enables third-party verification that a binary was built from the claimed source.

```bash
# Build with reproducibility settings
RUSTFLAGS="--remap-path-prefix=/build/workdir=." \
CARGO_PROFILE_RELEASE_LTO=true \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
cargo build --release --frozen --target x86_64-unknown-linux-gnu
```

`--frozen` already implies `--locked` and `--offline`, so you do not need to spell those flags separately.

Key settings for reproducibility:

```toml
# Cargo.toml
[profile.release]
lto = true
codegen-units = 1
strip = "symbols"
panic = "abort"

# .cargo/config.toml
[env]
RUSTFLAGS = "--remap-path-prefix=/build/workdir=."
SOURCE_DATE_EPOCH = "1700000000"  # Helps external tools that honor it
```

Absolute paths in debug info, non-deterministic linkers, and `build.rs` scripts are common causes of Rust build drift. `SOURCE_DATE_EPOCH` can help surrounding tools, but reproducible Rust builds primarily depend on path remapping, fixed toolchains, deterministic build scripts, and a committed lockfile.

Be precise about `strip`: `strip = true` means `debuginfo`, not full symbol stripping. Use `strip = "symbols"` when you intentionally want the more aggressive setting shown here.

For crash forensics, keep a separate profile or symbol artifact with debug info intact. A release artifact cannot be both aggressively stripped for distribution and rich in local symbols for post-mortem analysis at the same time.

### 16.5.2 Binary Verification

```bash
# Compare builds
sha256sum target/release/my-binary

# Build in Docker for consistency
docker run --rm -v "$(pwd)":/home/rust/src messense/rust-musl-cross:x86_64-musl cargo build --release
```

## 16.6 Private Registries and Air-Gapped Builds

### 16.6.1 Vendoring Dependencies

For air-gapped environments:

```bash
# Vendor all dependencies into the source tree
mkdir -p .cargo
cargo vendor vendor > .cargo/config.toml

# The vendor/ directory is now self-contained
# Build without network access
cargo build --offline --frozen
```

🔒 **Security benefit**: No network access needed during build. The vendored dependencies can be audited, scanned, and archived.

### 16.6.2 Private Registry

For organizations:

```toml
# .cargo/config.toml
[registries]
my-registry = { index = "https://my-company.com/crates-index" }

[dependencies]
my-crate = { version = "1.0", registry = "my-registry" }
```

## 16.7 Build Script (`build.rs`) Security

`build.rs` scripts run arbitrary code at build time. This is a significant attack surface:

```rust
// build.rs
fn main() {
    // This runs at compile time with full system access
    // A compromised dependency's build.rs could:
    // - Read environment variables (secrets, API keys)
    // - Exfiltrate source code
    // - Modify generated code
    // - Install backdoors
    
    println!("cargo:rerun-if-changed=src/wrapper.h");
}
```

🔒 **Mitigation strategies**:
1. Audit all `build.rs` scripts in your dependency tree.
2. Use `cargo deny check bans` with a `[bans.build]` policy to inventory and gate compile-time crates, scripts, and embedded executables.
3. Build in sandboxed environments (Docker, chroot).
4. Use `--frozen` to require an existing lockfile and prevent network access during builds:

```bash
cargo build --frozen
```

### 16.7.1 Procedural Macro Security

Procedural macros are the other major compile-time trust boundary. A proc-macro crate is compiled and then executed by `rustc` during macro expansion, so it can read environment variables, inspect the filesystem, and perform network I/O just like a hostile `build.rs`.

Common derive crates such as `serde`, `thiserror`, and `tokio-macros` are widely trusted, but they are still code execution on the build host. Audit proc-macro crates alongside `build.rs`, minimize them in high-assurance workspaces, and keep CI/build environments sandboxed so compile-time code cannot reach long-lived credentials or unrelated source trees.

## 16.8 CI/CD Pipeline Security

```yaml
# .github/workflows/build.yml
name: Secure Build

on: [push, pull_request]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0  # Full history for auditing
      
      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable branch snapshot
      
      # Verify the existing lock file can be used as-is
      - name: Verify lock file
        run: cargo check --locked
      
      # Audit dependencies
      - name: Security audit
        run: |
          cargo install cargo-audit --version 0.22.1 --locked
          cargo audit
      
      # Check dependency policy
      - name: Deny check
        run: |
          cargo install cargo-deny --version 0.19.0 --locked
          cargo deny check
      
      # Build and test
      - name: Build
        run: cargo build --release
      
      - name: Test
        run: cargo test
      
      # Generate SBOM (Software Bill of Materials)
      - name: Generate SBOM
        run: |
          cargo install cargo-cyclonedx --version 0.5.9 --locked
          cargo cyclonedx
```

Treat CI tooling the same way you treat application dependencies: pin GitHub Actions to reviewed SHAs, pin Cargo-installed tools to reviewed versions, and refresh those pins deliberately.

For release artifacts, pair SBOM generation with binary metadata or provenance. `cargo auditable`, Sigstore signing, and SLSA-style attestations strengthen the link between the reviewed source tree and the artifact you actually ship.

### 16.8.1 Trusted Publishing for crates.io

For release workflows, prefer crates.io Trusted Publishing via OpenID Connect (OIDC) instead of storing long-lived registry API tokens in CI secrets. crates.io supports trusted publishing from GitHub Actions and GitLab CI.

```yaml
# .github/workflows/publish.yml
name: Publish

on:
  push:
    tags: ["v*"]

permissions:
  contents: read
  id-token: write

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # reviewed snapshot
        with:
          toolchain: stable
      - run: cargo publish --locked
```

Configure the trust relationship once in crates.io, then remove stored crates.io tokens from repository secrets. If your CI provider cannot use OIDC, prefer short-lived credentials issued by a secret manager over repository-scoped long-lived tokens.

Keep dependency updates small and reviewable: enable Dependabot or Renovate for Rust crates, GitHub Actions, and container base images so that supply-chain changes arrive as normal code review.

## 16.9 Summary

- Evaluate every dependency for trustworthiness before adoption.
- Minimize dependency count; prefer the standard library.
- Commit `Cargo.lock` for reproducible builds.
- Use `cargo-deny` to enforce license, source, and ban policies.
- Use `cargo-supply-chain` to see who publishes and maintains the crates you implicitly trust.
- Vendor dependencies for air-gapped builds.
- Audit `build.rs` scripts— they have full system access at build time.
- Build in sandboxed environments with `--frozen --offline`.
- Generate and maintain a Software Bill of Materials (SBOM).
- Implement supply chain security checks in CI/CD.
- Prefer Trusted Publishing (OIDC) over long-lived crates.io tokens in CI.
- Use automated update PRs so dependency drift is reviewed incrementally.

In the next chapter, we begin Part V with a hands-on project: building a hardened TCP server that applies everything we've learned.

## 16.10 Exercises

1. **Dependency Vetting**: Choose a crate you use in production (or pick `serde_json` or `tokio`). Perform a full `cargo vet`-style review: read the `unsafe` code, check the test coverage, review the issue tracker for security bugs, and verify the maintainer's identity. Write a one-page audit summary with your recommendation (safe-to-deploy, review-needed, or do-not-use).

2. **Vendored Build**: Configure a project to build fully offline using `cargo vendor`. Verify the build succeeds without network access. Modify one vendored dependency maliciously (add a `println!` that exfiltrates data) and demonstrate that the change is detectable via checksum verification.

3. **Supply Chain CI Pipeline**: Create a GitHub Actions workflow that runs on every PR: `cargo audit` (block on vulnerabilities), `cargo deny check` (enforce license and source policies), `cargo geiger` (report unsafe code count), and `cargo cyclonedx` (generate SBOM). Make the workflow fail if any check does not pass. As a bonus, add a tag-based publish workflow that uses Trusted Publishing instead of a stored crates.io token.
