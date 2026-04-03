# Chapter 15 — Static Analysis and Auditing

> *"The compiler is your first auditor. Make it work harder."*

Static analysis examines code without executing it, finding potential vulnerabilities through pattern matching, data flow analysis, and formal methods. Rust's compiler already performs more static analysis than C compilers, but additional tools can catch subtler issues—especially in `unsafe` code and dependency management.

## 15.1 Compiler Warnings as Security Tools

### 15.1.1 Essential Warning Flags

```toml
# .cargo/config.toml
[build]
rustflags = [
    "-D", "warnings",                    # Treat all warnings as errors
    "-D", "future-incompatible",         # Future-breaking changes
    "-D", "unused",                      # Unused code = dead code = potential confusion
]

# Note: Clippy lints cannot be set via rustflags — they only work with `cargo clippy`.
# Use a CI step or Makefile target instead:
#   cargo clippy -- -W clippy::all -W clippy::pedantic
```

### 15.1.2 Security-Relevant Compiler Lints

| Lint | Security Relevance |
|------|-------------------|
| `unused_unsafe` | Unnecessary `unsafe` blocks |
| `unused_mut` | Unnecessary mutability |
| `unreachable_patterns` | Logic errors in match |
| `dead_code` | Unused code (potential confusion) |
| `unused_variables` | Unused values (potential logic error) |
| `unused_imports` | Unused dependencies |
| `elided_lifetimes_in_paths` | Hidden lifetime relationships |

## 15.2 Clippy for Security Auditing

Clippy is Rust's primary linting tool and catches many security-relevant patterns:

```bash
# Baseline CI gate
cargo clippy --workspace --all-targets --all-features -- \
    -W clippy::unwrap_used \
    -W clippy::expect_used \
    -W clippy::panic \
    -D warnings

# Review-oriented audit pass for low-level and parser-heavy code
cargo clippy --workspace --all-targets --all-features -- \
    -W clippy::indexing_slicing \
    -W clippy::arithmetic_side_effects \
    -W clippy::unwrap_in_result \
    -W clippy::wildcard_enum_match_arm
```

The second pass is meant to surface code worth reviewing, not to force every warning to zero mechanically. Bounds-checked parsing code often still triggers these heuristics because Clippy does not prove all surrounding invariants.

### 15.2.1 Key Security Lints

```rust
# type Error = &'static str;
#
// clippy::unwrap_used - Catches unchecked unwrap() calls
fn bad_example(result: Result<i32, Error>) -> i32 {
    result.unwrap()  // WARNING: called unwrap() on a Result
}

// clippy::indexing_slicing - Catches unchecked array indexing
fn bad_indexing(arr: &[u8], i: usize) -> u8 {
    arr[i]  // WARNING: indexing may panic
}

// clippy::arithmetic_side_effects - Catches unchecked arithmetic
fn bad_math(a: u64, b: u64) -> u64 {
    a * b  // WARNING: integer arithmetic detected
}

// Better alternative: preserve the failure state explicitly.
fn good_example(result: Result<i32, Error>) -> Result<i32, Error> {
    let value = result.map_err(|_| "validation failed")?;
    Ok(value)
}

fn good_indexing(arr: &[u8], i: usize) -> Option<u8> {
    arr.get(i).copied()  // Safe: returns Option
}

fn good_math(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)  // Safe: returns None on overflow
}
```

### 15.2.2 Custom Clippy Configuration

Create `clippy.toml` in your project root:

```toml
# clippy.toml
# Disallow these methods in security-critical code
disallowed-methods = [
    { path = "std::slice::get_unchecked", reason = "unsafe method requires manual bounds verification" },
    { path = "std::slice::get_unchecked_mut", reason = "unsafe method requires manual bounds verification" },
    { path = "std::ptr::read", reason = "unsafe, use safe alternative" },
    { path = "std::ptr::write", reason = "unsafe, use safe alternative" },
]

# Cognitive complexity limit (complex code hides bugs)
cognitive-complexity-threshold = 25

# Maximum number of lines per function
too-many-lines-threshold = 100

# Disallowed crate features
disallowed-types = [
    { path = "std::sync::Once", reason = "Use OnceLock which is safer" },
]
```

## 15.3 Dependency Auditing

### 15.3.1 `cargo audit`

```bash
cargo install cargo-audit --version 0.22.1 --locked
cargo audit
```

Output example:

```text
    Loaded 517 advisory records
    Scanning Cargo.lock for vulnerabilities (484 crates)

ID:       RUSTSEC-2023-0019
Crate:    openssl
Version:  0.10.52
Title:    OpenSSL HBAR TLS handshake downgrade
Date:     2023-02-07
URL:      https://rustsec.org/advisories/RUSTSEC-2023-0019
Severity: 7.5 (high)
Solution: upgrade to >= 0.10.55
```

🔒 **Security practice**: Run `cargo audit` in CI and block merging on high-severity findings.

### 15.3.2 `cargo geiger` — Counting Unsafe Code

```bash
cargo install cargo-geiger --version 0.13.0 --locked
cargo geiger --all-features
```

```text
Metric output format: x/y
    x = unsafe code used by the build
    y = total unsafe code found

Functions  Expressions  Impls  Traits  Methods  Dependency
0/0        0/0          0/0    0/0     0/0       my_secure_app
0/0        0/0          0/0    0/0     0/0       ├── my_lib
42/42      180/180      0/0    0/0     12/12     ├── ring  ⚠️  crypto, expected
3/3        15/15        0/0    0/0     1/1       ├── parking_lot
0/0        0/0          0/0    0/0     0/0       └── serde
```

🔒 **Security practice**: Review any crate with significant unsafe code. Especially scrutinize crates with:
- Unsafe functions exposed in the public API
- Raw pointer manipulation
- FFI to C libraries
- Custom allocators

### 15.3.3 `cargo crev` — Community Code Review

```bash
cargo install cargo-crev --version 0.26.5 --locked
cargo crev import trust --from-url https://github.com/crev-dev/crev-proofs
cargo crev verify
```

`crev` is a web-of-trust system where community members review crates and publish their findings. You can:
- See which crates have been reviewed by trusted reviewers
- Review crates yourself and publish findings
- Configure trust requirements for your project

### 15.3.4 `cargo vet` — Supply Chain Auditing

```bash
cargo install cargo-vet --version 0.10.2 --locked
cargo vet init
cargo vet
```

`cargo vet` requires that every dependency has been explicitly reviewed:

```toml
# supply-chain/audits.toml
[[audits.my-crypto-lib]]
who = "Security Team <security@example.com>"
criteria = "safe-to-deploy"
version = "1.2.3"
notes = "Reviewed for memory safety, no unsafe code, constant-time operations verified"
```

## 15.4 Additional Audit Tooling

### 15.4.1 `cargo-careful` — Extra Runtime Checking

`cargo-careful` complements Miri: it runs your normal test or binary workflow with a specially prepared standard library and extra checks enabled, but at much closer-to-native speed than an interpreter.

```bash
cargo install cargo-careful
cargo +nightly careful test
```

What it is good for:

- Re-running larger integration suites with extra checking around undefined behavior
- Exercising `unsafe`-heavy code paths that are too slow or too environment-dependent for Miri
- Building a nightly-only audit job that is stricter than regular `cargo test`

Optional sanitizer integration is also available:

```bash
cargo +nightly careful test -Zcareful-sanitizer=address
```

⚠️ **Operational notes**:
- `cargo-careful` requires a recent nightly toolchain.
- On first use it may need the `rustc-src` component so it can prepare the careful sysroot.
- Treat it as **complementary** to Miri, not a replacement. Use Miri for smaller, precise UB-focused tests; use `cargo-careful` for broader suites that need more realistic execution.

### 15.4.2 `cargo-semver-checks`

For library maintainers, `cargo-semver-checks` detects accidental API-breaking changes between versions. This is critical because a breaking change in a security library can silently break downstream security guarantees:

```bash
cargo install cargo-semver-checks --version 0.47.0 --locked

# Check current code against the last published version
cargo semver-checks

# Compare against a specific baseline version
cargo semver-checks --baseline-version 1.2.0

# Compare against a specific branch or commit
cargo semver-checks --baseline-rev abc1234
```

### How It Works

`cargo-semver-checks` compares the public API surface of two versions of your crate using the Rustdoc JSON output. It checks for over 80 types of breaking changes, including:

- **Removed public items**: A public function, type, or trait was deleted.
- **Changed function signatures**: A parameter type changed, a new required parameter was added, or the return type changed.
- **Changed trait bounds**: A trait implementation was removed or bounds were tightened.
- **Changed enum variants**: A variant was removed or its fields changed.
- **Changed struct fields**: A public field was removed or made private.

Example output:

```text
--- failure struct_pub_field_missing: pub field removed from pub struct ---

Description:
A public struct field has been removed. This breaks code that accesses or constructs the struct using the field name.

Ref: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.36.0/src/lints/struct_pub_field_missing.ron

Failed in:
  struct SecurityConfig: missing field key_rotation_days in ./src/config.rs:15
  struct SecurityConfig: missing field max_retries in ./src/config.rs:15

--- failure trait_method_missing: pub trait method removed ---

Description:
A method was removed from a public trait. This breaks any implementation of that trait.

Ref: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.36.0/src/lints/trait_method_missing.ron

Failed in:
  trait Authenticator: missing method validate_token in ./src/auth.rs:8
```

🔒 **Security relevance**: If your security library removes a validation method or changes a function signature, downstream code may silently skip a security check. Running `cargo-semver-checks` in CI ensures you catch these before publishing.

```yaml
# .github/workflows/security.yml addition
- name: Semver checks
  run: |
    cargo install cargo-semver-checks --version 0.47.0 --locked
    cargo semver-checks
```

## 15.5 Manual Code Audit Checklist for Rust

### 15.5.1 Unsafe Code Audit

For each `unsafe` block:

- [ ] **Scope**: Is the unsafe block as small as possible?
- [ ] **Safety comment**: Is there a `# Safety` comment explaining why it's safe?
- [ ] **Bounds**: Are all pointer accesses within bounds?
- [ ] **Alignment**: Are pointer casts properly aligned?
- [ ] **Alias**: Are mutable references unique (no aliasing violations)?
- [ ] **Initialization**: Is all read memory initialized?
- [ ] **Thread safety**: Is shared state synchronized?
- [ ] **Lifetime**: Do references not outlive the data?
- [ ] **Soundness**: Can safe code trigger UB through this?

### 15.5.2 Cryptographic Code Audit

- [ ] Are AEAD ciphers used (not raw AES-CBC)?
- [ ] Are nonces unique per key?
- [ ] Are keys zeroed after use (`zeroize`)?
- [ ] Are comparisons constant-time?
- [ ] Are random numbers from a CSPRNG?
- [ ] Are passwords hashed with proper KDF (Argon2id, bcrypt)?
- [ ] Are key derivation parameters appropriate (iterations, salt)?

### 15.5.3 Error Handling Audit

- [ ] Are all fallible operations handled (no `unwrap()` in production)?
- [ ] Do error messages avoid leaking internal details?
- [ ] Are crypto errors generic (no oracle attacks)?
- [ ] Are panics caught at FFI boundaries?

### 15.5.4 Concurrency Audit

- [ ] Is lock ordering consistent (no deadlock potential)?
- [ ] Are there bounded channels (not unbounded)?
- [ ] Are `Send`/`Sync` implementations correct for custom types?
- [ ] Is shared mutable state properly synchronized?

## 15.6 Formal Methods: Kani and Prusti

### 15.6.1 Kani for Bounded Model Checking

Kani is especially useful for parser arithmetic, bounds checks, and state-machine invariants because it exhaustively explores bounded inputs instead of relying on random testing:

```bash
# Install Kani
cargo install kani-verifier --locked

# Run proofs in the current crate
cargo kani
```

```rust,ignore
#[kani::proof]
fn frame_length_never_overflows() {
    let payload_len: usize = kani::any();
    kani::assume(payload_len <= 16 * 1024);

    let frame_len = payload_len.checked_add(4).unwrap();
    assert!(frame_len >= 4);
    assert!(frame_len <= 16 * 1024 + 4);
}
```

Use Kani when you want high assurance on bounded properties such as "length arithmetic never overflows", "this index stays in bounds", or "all enum states transition legally".

### 15.6.2 Prusti for Contracts

For contract-style verification, Prusti lets you express preconditions, postconditions, and invariants:

```bash
# Install Prusti (requires specific Rust version)
# See: https://github.com/viperproject/prusti-dev
```

Prusti allows you to specify preconditions, postconditions, and invariants that the verifier proves:

```rust
// Requires Prusti annotations
// #[requires(idx < slice.len())]
// #[ensures(result == slice[idx])]
fn safe_get(slice: &[u8], idx: usize) -> u8 {
    slice[idx]
}
```

## 15.7 Summary

- Treat compiler warnings as security findings; enable `-D warnings`.
- Use Clippy with security-focused lints (`unwrap_used`, `indexing_slicing`, `arithmetic_side_effects`).
- Run `cargo audit` in CI to catch known dependency vulnerabilities.
- Use `cargo geiger` to quantify unsafe code in dependencies.
- Use `cargo vet` or `cargo crev` for supply chain auditing.
- Use `cargo-careful` on nightly for broader runtime checking of unsafe-heavy code and integration tests.
- Use `cargo semver-checks` to detect accidental breaking API changes that could compromise downstream security.
- Follow the code audit checklists for unsafe, crypto, error handling, and concurrency.
- Use Kani for bounded proofs and Prusti for contract-style verification when you need the highest assurance.

In the next chapter, we cover supply chain security—protecting your build pipeline from tampering and compromise.

## 15.8 Exercises

1. **Clippy Security Audit**: Configure Clippy with the security lint set from this chapter (`unwrap_used`, `indexing_slicing`, `arithmetic_side_effects`, `panic`). Run it on a codebase you maintain (or use one of the earlier chapter exercises). Catalog every warning, classify each as true positive or false positive, and fix the true positives. Write a summary of which lints caught the most issues.

2. **Dependency Audit Report**: Run `cargo audit`, `cargo geiger`, and `cargo deny check` on a real project. For each crate that contains `unsafe` code (per `cargo geiger`), investigate whether it has been audited, how many open issues it has, and when it was last updated. Write a risk assessment for the top 3 most concerning dependencies.

3. **Custom Audit Checklist**: Create a project-specific audit checklist by combining the checklists from §15.5 with your own domain-specific requirements (e.g., "no `unwrap` in authentication paths", "all file paths validated against directory traversal"). Apply it to one of the projects from Chapters 17 or 18 and report findings.

4. **Careful Nightly Audit**: Install `cargo-careful` and run `cargo +nightly careful test` on a crate that contains parsing logic or `unsafe` code. Compare the result and runtime against regular `cargo test` and, if feasible, against `cargo +nightly miri test`. Document which bugs each tool class is best at finding.
