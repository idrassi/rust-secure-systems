# Chapter 13 — Testing Strategies for Secure Code

> *"Program testing can be used to show the presence of bugs, but never to show their absence."* — Edsger W. Dijkstra

Testing security-critical code requires a different mindset than testing functionality. You're not just verifying that the code works correctly for valid inputs—you must also verify that it fails safely for every possible invalid, malicious, or unexpected input. This chapter covers Rust testing strategies with a security focus.

## 13.1 Rust Testing Fundamentals

### 13.1.1 Unit Tests

Rust has built-in test support:

```rust
// In src/lib.rs or src/parse.rs
#[derive(Debug, PartialEq)]
pub enum ParseError {
    NotANumber,
    OutOfRange(u32),
}

pub fn parse_port(input: &str) -> Result<u16, ParseError> {
    let value: u32 = input.parse().map_err(|_| ParseError::NotANumber)?;
    if value > 65535 {
        return Err(ParseError::OutOfRange(value));
    }
    Ok(value as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn valid_port() {
        assert_eq!(parse_port("80").unwrap(), 80);
        assert_eq!(parse_port("443").unwrap(), 443);
        assert_eq!(parse_port("65535").unwrap(), 65535);
    }
    
    #[test]
    fn port_zero() {
        assert_eq!(parse_port("0").unwrap(), 0);
    }
    
    #[test]
    fn port_too_large() {
        assert!(matches!(parse_port("65536"), Err(ParseError::OutOfRange(65536))));
        assert!(matches!(parse_port("99999"), Err(ParseError::OutOfRange(_))));
    }
    
    #[test]
    fn port_not_a_number() {
        assert!(matches!(parse_port("abc"), Err(ParseError::NotANumber)));
        assert!(matches!(parse_port(""), Err(ParseError::NotANumber)));
    }
    
    #[test]
    fn port_negative() {
        assert!(matches!(parse_port("-1"), Err(ParseError::NotANumber)));
    }
    
    #[test]
    fn port_overflow() {
        assert!(matches!(
            parse_port("9999999999999999999999"),
            Err(ParseError::NotANumber)
        ));
    }
}
```

Run with: `cargo test`

Rust also gives you two pragmatic test attributes that matter in security work:

```rust
#[test]
#[should_panic(expected = "internal invariant violated")]
fn invariant_checks_trip_in_tests() {
    panic!("internal invariant violated");
}

#[test]
#[ignore = "slow integration test against external dependency"]
fn hsm_roundtrip() {
    // Run explicitly with: cargo test -- --ignored
}
```

Use `#[should_panic]` for invariants and programmer errors, not for attacker-controlled input paths that should return `Result`.

### 13.1.2 Integration Tests

Tests in `tests/` have access to your crate's public API only:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::my_secure_app as my_secure_app;
// tests/integration.rs
use my_secure_app::{Authenticator, Session};

#[test]
fn test_authentication_flow() {
    let auth = Authenticator::new();
    
    // Successful authentication
    let session = auth.authenticate("admin", "correct_password")
        .expect("authentication should succeed");
    
    assert!(session.is_valid());
    
    // Failed authentication
    let result = auth.authenticate("admin", "wrong_password");
    assert!(result.is_err());
}
```

### 13.1.3 Test Organization for Security

```text
tests/
├── authentication.rs        # Auth-related tests
├── authorization.rs         # Permission checks
├── input_validation.rs      # Input boundary tests
├── crypto.rs                # Crypto operation tests
├── concurrency.rs           # Thread safety tests
└── common/
    └── mod.rs               # Shared test utilities
```

## 13.2 Security-Specific Test Patterns

### 13.2.1 Boundary Value Testing

```rust,ignore
#[cfg(test)]
mod boundary_tests {
    use super::*;
    
    #[test]
    fn buffer_at_exact_limit() {
        let data = vec![0u8; MAX_BUFFER_SIZE];
        assert!(process_buffer(&data).is_ok());
    }
    
    #[test]
    fn buffer_one_over_limit() {
        let data = vec![0u8; MAX_BUFFER_SIZE + 1];
        assert!(process_buffer(&data).is_err());
    }
    
    #[test]
    fn buffer_empty() {
        assert!(process_buffer(&[]).is_err());
    }
    
    #[test]
    fn buffer_max_usize() {
        // Test that we don't overflow on size calculations
        let result = std::panic::catch_unwind(|| {
            allocate_buffer(usize::MAX)
        });
        assert!(result.is_err() || result.unwrap().is_err());
    }
    
    #[test]
    fn integer_boundary_values() {
        assert_eq!(safe_add(u64::MAX, 0), Some(u64::MAX));
        assert_eq!(safe_add(u64::MAX, 1), None);  // Overflow
        assert_eq!(safe_add(0, 0), Some(0));
        assert_eq!(safe_add(u64::MAX / 2, u64::MAX / 2 + 1), Some(u64::MAX));
    }
}
```

### 13.2.2 Negative Testing — Testing Failure Modes

```rust,ignore
#[cfg(test)]
mod negative_tests {
    use super::*;
    
    #[test]
    fn reject_null_bytes_in_hostname() {
        let result = Hostname::new("evil\0.example.com");
        assert!(result.is_err());
    }
    
    #[test]
    fn reject_path_traversal() {
        let base = std::path::Path::new("/var/data");
        assert!(safe_path(base, "../../../etc/passwd").is_err());
        assert!(safe_path(base, "..\\..\\windows\\system32").is_err());
        assert!(safe_path(base, "/etc/passwd").is_err());
    }
    
    #[test]
    fn reject_oversized_input() {
        let huge = "A".repeat(1_000_000);
        let result = parse_username(&huge);
        assert!(result.is_err());
    }
    
    #[test]
    fn reject_special_characters() {
        for char in &['\0', '\n', '\r', '\t', '\\', '\'', '"'] {
            let input = format!("user{}name", char);
            let result = parse_username(&input);
            assert!(result.is_err(), "Should reject character: {:?}", char);
        }
    }
    
    #[test]
    fn reject_empty_input() {
        assert!(parse_username("").is_err());
        assert!(parse_username("   ").is_err());
    }
}
```

### 13.2.3 Property-Based Security Invariants

```rust,ignore
#[cfg(test)]
mod invariant_tests {
    use super::*;
    
    /// Property: encryption followed by decryption always returns the original plaintext
    #[test]
    fn encrypt_decrypt_roundtrip() {
        for _ in 0..100 {
            let key = generate_random_key();
            let plaintext = generate_random_bytes(256);
            let nonce = generate_nonce();
            
            let ciphertext = encrypt(&key, &nonce, &plaintext).unwrap();
            let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
            
            assert_eq!(plaintext, decrypted);
        }
    }
    
    /// Property: encrypted data is never identical to plaintext
    #[test]
    fn encryption_is_not_identity() {
        let key = generate_random_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, World!";
        
        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        
        assert_ne!(&plaintext[..], &ciphertext[..plaintext.len()]);
    }
    
    /// Property: same plaintext with different nonces produces different ciphertext
    #[test]
    fn nonce_varies_ciphertext() {
        let key = generate_random_key();
        let plaintext = b"Same message";
        
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        
        let ct1 = encrypt(&key, &nonce1, plaintext).unwrap();
        let ct2 = encrypt(&key, &nonce2, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }
    
    /// Property: any modification to ciphertext causes decryption to fail
    #[test]
    fn tamper_detection() {
        let key = generate_random_key();
        let nonce = generate_nonce();
        let plaintext = b"sensitive data";
        
        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        
        // Flip one bit
        ciphertext[0] ^= 0x01;
        
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "Tampered ciphertext should be rejected");
    }
}
```

### 13.2.4 Testing Error Messages Don't Leak Sensitive Data

```rust,ignore
#[cfg(test)]
mod information_disclosure_tests {
    use super::*;
    
    #[test]
    fn error_messages_dont_contain_secrets() {
        let secret_key = "super_secret_key_12345";
        let result = authenticate(secret_key, "wrong_data");
        
        let error_string = format!("{:?}", result);
        assert!(!error_string.contains(secret_key));
        assert!(!error_string.contains("secret"));
    }
    
    #[test]
    fn authentication_errors_are_generic() {
        let result1 = authenticate("unknown_user", "password");
        let result2 = authenticate("known_user", "wrong_password");
        
        // Both should return the same generic error
        // (prevents user enumeration)
        assert_eq!(
            format!("{}", result1.unwrap_err()),
            format!("{}", result2.unwrap_err())
        );
    }
}
```

## 13.3 Testing Concurrent Code

```rust,ignore
#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    
    #[test]
    fn concurrent_access_to_shared_state() {
        let state = Arc::new(MutexProtectedState::new());
        let mut handles = vec![];
        
        for _ in 0..100 {
            let state = Arc::clone(&state);
            handles.push(thread::spawn(move || {
                state.increment();
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(state.count(), 100);
    }
    
    #[test]
    fn test_no_data_race() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        
        for _ in 0..10 {
            let counter = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(counter.load(Ordering::SeqCst), 10_000);
    }
}
```

## 13.4 Testing Unsafe Code

```rust,ignore
#[cfg(test)]
mod unsafe_tests {
    use super::*;
    
    #[test]
    fn test_safe_wrapper_prevents_oob() {
        let mut buffer = SafeBuffer::new(10);
        buffer.write(0, &[1, 2, 3]).unwrap();
        
        // In-bounds access works
        assert_eq!(buffer.read(0, 3).unwrap(), &[1, 2, 3]);
        
        // Out-of-bounds access fails gracefully
        assert!(buffer.read(8, 4).is_err());  // Would need 12 bytes, only have 10
        assert!(buffer.write(10, &[1]).is_err());  // Start at end
    }
    
    #[test]
    fn test_safe_wrapper_null_handling() {
        let result = SafeBuffer::from_raw(std::ptr::null_mut(), 10);
        assert!(result.is_err());
    }
}
```

## 13.5 Doc Tests — Testable Documentation

```rust,no_run
/// Validates that a username contains only alphanumeric characters and underscores.
///
/// # Examples
///
/// ```
/// use my_secure_app::validate_username;
///
/// assert!(validate_username("john_doe123").is_ok());
/// assert!(validate_username("").is_err());
/// assert!(validate_username("user@evil").is_err());
/// assert!(validate_username("a".repeat(65).as_str()).is_err());
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    Empty,
    TooLong,
    InvalidCharacters,
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.is_empty() {
        return Err(ValidationError::Empty);
    }
    if username.len() > 64 {
        return Err(ValidationError::TooLong);
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ValidationError::InvalidCharacters);
    }
    Ok(())
}
```

Doc tests run with `cargo test` and serve as both documentation and regression tests.

## 13.6 Continuous Testing in CI

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rust: [stable, beta, nightly]
    
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # reviewed snapshot
        with:
          toolchain: ${{ matrix.rust }}
      
      - name: Build
        run: cargo build --verbose
      
      - name: Run tests
        run: cargo test --verbose
      
      - name: Run tests (all features)
        run: cargo test --all-features --verbose
      
      - name: Run tests (release mode)
        run: cargo test --release --verbose
      
      - name: Run Miri (nightly only)
        if: matrix.rust == 'nightly'
        run: |
          rustup component add miri --toolchain nightly
          cargo +nightly miri test
```

### 13.6.1 Faster, More Isolated Runs with `cargo-nextest`

`cargo test` is the baseline, but larger security suites often benefit from `cargo-nextest`:

- Better failure reporting and timeout handling
- Process-level isolation between tests
- Easier sharding across CI workers

```bash
cargo install cargo-nextest --version 0.9.132 --locked
cargo nextest run --workspace --all-features
```

For parser, auth, and protocol suites, this isolation helps catch hidden cross-test coupling and makes flaky failures easier to diagnose.

### 13.6.2 Coverage Reporting with `cargo-llvm-cov`

Coverage does not prove security, but it quickly shows which validation branches, parser error paths, and unsafe wrappers are still untested:

```bash
cargo install cargo-llvm-cov --version 0.8.5 --locked
cargo llvm-cov --workspace --all-features --html
```

Prioritize coverage review on authentication, parsing, deserialization, unsafe wrappers, and failure paths rather than chasing a global percentage.

### 13.6.3 Mutation Testing with `cargo-mutants`

Coverage tells you what executed; mutation testing tells you whether the tests would fail if the security logic were wrong. `cargo-mutants` flips conditionals, comparison operators, and other small pieces of code, then reruns your tests to see whether the suite notices:

```bash
cargo install cargo-mutants --version 27.0.0 --locked
cargo mutants --workspace --all-features
```

This is especially valuable for authentication checks, parser bounds checks, rate limiting, and unsafe wrappers. A surviving mutant around `>=` vs `>`, allow/deny logic, or an omitted validation branch is a strong signal that the tests are not actually enforcing the intended security property.

## 13.7 Summary

- Write comprehensive unit tests for all security-critical functions.
- Test boundary values: empty, minimum, maximum, and overflow cases.
- Use negative testing to verify rejection of malicious inputs.
- Test security invariants as properties (encryption roundtrips, tamper detection).
- Verify error messages don't leak sensitive information.
- Test concurrent code with many threads to surface data races.
- Test unsafe code wrappers to ensure the safe interface prevents UB.
- Use doc tests for testable documentation.
- Run tests across stable, beta, and nightly with Miri for UB detection.
- Use `cargo-nextest` for faster, better-isolated CI runs on large suites.
- Use `cargo-llvm-cov` to find untested validation and error-handling paths.
- Use `cargo-mutants` to check whether tests actually fail when critical logic is changed.

In the next chapter, we go beyond manual test cases to explore fuzzing and property-based testing—automated techniques for finding bugs you didn't think to test for.

## 13.8 Exercises

1. **Boundary Test Suite**: Write a function `parse_ipv4(s: &str) -> Result<[u8; 4], ParseError>` that parses dotted-quad IPv4 addresses. Write a comprehensive test suite covering: all valid addresses, leading zeros, negative numbers, too many octets, too few octets, non-numeric input, overflow (>255), empty string, embedded null bytes, and Unicode characters.

2. **Error Message Audit**: Write a function that handles authentication failures. Write tests that verify: error messages logged server-side contain useful debugging info, but the `Display` representation sent to clients contains only generic messages ("Authentication failed"). Use `assert!(!format!("{}", err).contains("password"))` to verify no sensitive data leaks.

3. **Concurrency Stress Test**: Write a thread-safe counter using `Arc<Mutex<u64>>`. Write a test that spawns 100 threads, each incrementing the counter 10,000 times. Assert the final value is exactly 1,000,000. Then replace the `Mutex` with an `AtomicU64` and benchmark the performance difference.
