# Chapter 14 - Fuzzing and Property-Based Testing

> *"The best test cases are the ones you didn't think to write."*

Manual testing can only cover inputs you anticipate. Fuzzing and property-based testing generate inputs automatically, discovering bugs through random exploration. For security-critical code (parsers, decoders, protocol handlers) these techniques are essential because attackers will send inputs you never imagined.

## 14.1 Property-Based Testing with `proptest`

Property-based testing generates random inputs that satisfy specified constraints and checks that properties (invariants) hold for all of them.

### 14.1.1 Basic Setup

```toml
# Cargo.toml
[dev-dependencies]
proptest = "1"
```

### 14.1.2 Testing Parser Properties

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::proptest as proptest;
# #[derive(Debug, PartialEq)]
# enum ParseError {
#     NotANumber,
#     OutOfRange(u32),
# }
# fn parse_port(input: &str) -> Result<u16, ParseError> {
#     let value: u32 = input.parse().map_err(|_| ParseError::NotANumber)?;
#     if value > 65535 {
#         return Err(ParseError::OutOfRange(value));
#     }
#     Ok(value as u16)
# }
# struct Hostname(String);
# impl Hostname {
#     fn new(input: &str) -> Result<Self, ()> {
#         if input.contains('\0') {
#             Err(())
#         } else {
#             Ok(Self(input.to_string()))
#         }
#     }
# }
# fn generate_nonce() -> [u8; 12] {
#     [0u8; 12]
# }
# fn encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, ()> {
#     let ciphertext = plaintext
#         .iter()
#         .enumerate()
#         .map(|(i, byte)| byte ^ key[i % key.len()] ^ nonce[i % nonce.len()])
#         .collect();
#     Ok(ciphertext)
# }
# fn decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
#     encrypt(key, nonce, ciphertext)
# }
# fn buffer_write(buf: &mut [u8], offset: usize, data: &[u8]) -> Result<(), ()> {
#     if offset > buf.len() {
#         return Err(());
#     }
#     let end = offset.saturating_add(data.len()).min(buf.len());
#     let len = end.saturating_sub(offset);
#     buf[offset..end].copy_from_slice(&data[..len]);
#     Ok(())
# }
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_port_roundtrip(port in 0u16..=65535) {
        let s = port.to_string();
        let parsed = parse_port(&s).unwrap();
        prop_assert_eq!(parsed, port);
    }
    
    #[test]
    fn parse_port_rejects_invalid(
        input in any::<String>().prop_filter("not a valid u16", |s| s.parse::<u16>().is_err())
    ) {
        prop_assert!(parse_port(&input).is_err());
    }
    
    #[test]
    fn hostname_rejects_null_bytes(s in ".*\\0.*") {
        prop_assert!(Hostname::new(&s).is_err());
    }
    
    #[test]
    fn encryption_roundtrip(
        key in prop::collection::vec(any::<u8>(), 32),
        plaintext in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let nonce = generate_nonce();
        let ciphertext = encrypt(&key, &nonce, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn buffer_operations_never_panic(
        size in 0usize..1024,
        offset in 0usize..2048,
        data in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let mut buf = vec![0u8; size];
        // This should never panic, even with invalid offsets
        let _ = buffer_write(&mut buf, offset, &data);
    }
}
```

### 14.1.3 Custom Strategies

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::proptest as proptest;
# use rust_secure_systems_book::parse_http_header;
use proptest::prelude::*;

/// Generate valid HTTP header strings
fn http_header_strategy() -> impl Strategy<Value = (String, String)> {
    // Header name: alphanumeric + dash
    let name = "[a-zA-Z][a-zA-Z0-9\\-]{0,50}";
    // Header value: printable ASCII, no CR/LF
    let value = "[!-~ \t]{0,200}";
    
    (name, value)
}

proptest! {
    #[test]
    fn http_headers_parsed_correctly((name, value) in http_header_strategy()) {
        let header_line = format!("{}: {}", name, value);
        let parsed = parse_http_header(&header_line).unwrap();
        prop_assert_eq!(parsed.name, name);
        prop_assert_eq!(parsed.value, value.trim_start_matches(|c| c == ' ' || c == '\t'));
    }
}

/// Generate valid IP packets
fn ip_packet_strategy() -> impl Strategy<Value = Vec<u8>> {
    // Version + IHL
    Just(0x45u8)
        // DSCP/ECN, Total Length (will be fixed up)
        .prop_flat_map(|version_ihl| {
            (Just(version_ihl), any::<u8>(), prop::collection::vec(any::<u8>(), 18..1500))
        })
        .prop_map(|(vihl, dscp_ecn, rest)| {
            let mut packet = vec![vihl, dscp_ecn, 0, 0]; // Length placeholder
            packet.extend_from_slice(&rest);
            let len = packet.len() as u16;
            packet[2..4].copy_from_slice(&len.to_be_bytes());
            packet
        })
}
```

### 14.1.4 Regression Testing with `proptest`

When `proptest` finds a failing case, it persists the failing input:

```text
# .proptest-regressions/port_parser.txt
# Seeds for failure in proptest test suite
cc 75 29 7a 79 9a 49 37 09 4e f1 00 63 96 55 38
```

This file should be committed to version control to ensure the failing case is always re-tested.

## 14.2 Fuzzing with `cargo-fuzz`

Fuzzing goes beyond property-based testing by using code coverage feedback to guide input generation toward unexplored code paths. This makes it dramatically more effective at finding bugs in complex parsers and decoders.

### 14.2.1 Setup

```bash
# Install cargo-fuzz (requires nightly)
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --version 0.13.1 --locked

# Create a fuzz target
cargo +nightly fuzz init
cargo +nightly fuzz add parse_message
```

### 14.2.2 Writing Fuzz Targets

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate libfuzzer_sys;
# use rust_secure_systems_book::my_secure_app as my_secure_app;
// fuzz/fuzz_targets/parse_message.rs
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // The fuzz target should call the function you want to test
    // with arbitrary byte input.
    //
    // If this function panics or causes UB, the fuzzer will report the input.
    let _ = my_secure_app::parse_message(data);
});
```

For structured fuzzing with `arbitrary`:

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate arbitrary;
# extern crate libfuzzer_sys;
# use rust_secure_systems_book::my_secure_app as my_secure_app;
// fuzz/fuzz_targets/parse_packet.rs
use arbitrary::Arbitrary;

#[derive(Debug, arbitrary::Arbitrary)]
struct PacketInput {
    version: u8,
    flags: u8,
    payload: Vec<u8>,
}

libfuzzer_sys::fuzz_target!(|input: PacketInput| {
    let mut raw = vec![input.version, input.flags];
    let len = (input.payload.len() as u16).to_be_bytes();
    raw.extend_from_slice(&len);
    raw.extend_from_slice(&input.payload);
    
    let _ = my_secure_app::parse_packet(&raw);
});
```

### 14.2.3 Running the Fuzzer

```bash
# Run fuzzer for a specified duration
cargo +nightly fuzz run parse_message -- -max_total_time=3600

# Run without sanitizers (for baseline)
cargo +nightly fuzz run parse_message -s none -- -max_total_time=3600

# Run with address sanitizer (detects buffer overflows, use-after-free)
cargo +nightly fuzz run parse_message -s address

# Reproduce a crash
cargo +nightly fuzz run parse_message fuzz/artifacts/parse_message/crash-<hash>
```

### 14.2.4 Fuzzing Best Practices

`cargo-fuzz` is the default choice for libFuzzer-based coverage-guided fuzzing in Rust, but it is not the only engine. AFL.rs is also worth knowing when you want AFL/AFL++ style workflows or need to compare engines on the same parser. `honggfuzz-rs` is another practical option when you want a mature multi-process engine with good multicore support.

🔒 **Fuzzing strategy for security-critical code**:

1. **Fuzz every parser**: Network protocol parsers, file format decoders, configuration file parsers, HTTP header parsers.

2. **Fuzz cryptographic implementations**: Verify that crypto operations don't panic, abort, or leak data with malformed inputs.

3. **Use corpus minimization**: After finding interesting inputs, minimize them:

```bash
# Minimize a corpus
cargo +nightly fuzz cmin parse_message

# Minimize a specific crash
cargo +nightly fuzz tmin parse_message fuzz/artifacts/parse_message/crash-<hash>
```

4. **Seed with real data**: Provide valid sample inputs as a starting corpus:

```bash
mkdir -p fuzz/corpus/parse_message
cp tests/fixtures/*.bin fuzz/corpus/parse_message/
```

5. **Run continuously in CI**:

```yaml
# .github/workflows/fuzz.yml
name: Fuzz
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # reviewed snapshot
        with:
          toolchain: nightly
      - run: cargo +nightly install cargo-fuzz --version 0.13.1 --locked
      
      - name: Fuzz parse_message (10 minutes)
        run: cargo +nightly fuzz run parse_message -- -max_total_time=600
      
      - name: Fuzz parse_packet (10 minutes)
        run: cargo +nightly fuzz run parse_packet -- -max_total_time=600
```

6. **Probe algorithmic complexity, not just crashes**: Regex validators, recursive parsers, and decompression logic can fail by becoming too slow rather than by panicking. The standard `regex` crate avoids classic catastrophic backtracking for its supported syntax, but that does not make regex processing free on attacker-controlled data: worst-case searches still scale with both pattern size and input size. Keep the input caps from Chapter 7 even when you use `regex`, and treat backtracking engines such as `fancy-regex` and custom parsers as higher-risk code paths that can still go superlinear. Add long, nearly-matching inputs to your corpus and keep dedicated timing or iteration-count tests for suspicious code paths.

### 14.2.5 Differential Fuzzing

When you have two implementations of the same format or algorithm, fuzz them against each other. This is especially valuable during rewrites, parser hardening, or "safe Rust replacement for legacy C" projects:

```rust,no_run
# extern crate libfuzzer_sys;
# fn legacy_c_parser(_data: &[u8]) -> Result<Vec<u8>, ()> { Ok(Vec::new()) }
# fn rust_parser(_data: &[u8]) -> Result<Vec<u8>, ()> { Ok(Vec::new()) }
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let reference = legacy_c_parser(data);
    let candidate = rust_parser(data);

    assert_eq!(candidate.is_ok(), reference.is_ok());

    if let (Ok(left), Ok(right)) = (candidate, reference) {
        assert_eq!(left, right);
    }
});
```

Differential fuzzing catches a different class of bug than ordinary crash fuzzing: semantic disagreement. One parser accepting inputs the other rejects, or two implementations normalizing fields differently, can be just as security-relevant as a panic.

## 14.3 Guided Fuzzing for Security

### 14.3.1 Fuzzing for Memory Safety (Miri + Fuzzing)

Combine Miri with fuzzing to detect undefined behavior. You need a test harness that reads corpus files and passes them to the parser:

```bash
# Use an environment variable rather than a positional CLI argument:
# extra words after `cargo test --` are interpreted by the libtest harness as
# test filters, so `cargo ... test -- "$file"` can skip the test entirely.
for file in fuzz/corpus/parse_message/*; do
    CORPUS_FILE="$file" cargo +nightly miri test --test miri_corpus -- --exact miri_corpus_entry
done
```

⚠️ **Practicality note**: Running Miri once per corpus file is extremely slow. Use it on minimized corpora, targeted reproducers, or periodic CI jobs rather than every large fuzz corpus on every edit.

```rust,ignore
// tests/miri_corpus.rs - test harness for running Miri on corpus files
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::my_secure_app as my_secure_app;
use std::env;
use std::fs;

#[test]
fn miri_corpus_entry() {
    if let Ok(path) = env::var("CORPUS_FILE") {
        let data = fs::read(&path).expect("failed to read corpus file");
        let _ = my_secure_app::parse_message(&data);
    }
}
```

### 14.3.2 Fuzzing for Side-Channel Resistance

While fuzzing doesn't directly detect timing side channels, you can fuzz the *error paths* to ensure they don't reveal information:

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate libfuzzer_sys;
# use rust_secure_systems_book::my_secure_app::authenticate;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Both of these should produce the same externally observable error type.
    let result1 = authenticate("unknown_user", data);
    let result2 = authenticate("known_user", data);
    
    // Error types should be identical (prevent user enumeration)
    assert_eq!(
        std::mem::discriminant(&result1),
        std::mem::discriminant(&result2)
    );
});
```

### 14.3.3 ThreadSanitizer and MemorySanitizer

AddressSanitizer is not the only sanitizer worth running. For concurrent or low-level code, add standalone sanitizer jobs alongside fuzzing:

```bash
# Data races in real threaded code
RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test

# Uninitialized-memory reads
RUSTFLAGS="-Zsanitizer=memory" cargo +nightly test
```

- **ThreadSanitizer (TSan)** catches data races in executed code paths, including cases involving real threads, FFI, and I/O that Miri cannot run directly.
- **MemorySanitizer (MSan)** catches uses of uninitialized memory, but it requires the whole stack to be instrumented. If you call into C/C++ code, those dependencies generally need MSan-enabled builds too.
- Sanitizer availability is target-dependent and still best treated as a nightly audit job. Keep the commands in CI or a dedicated review script rather than assuming every developer machine supports them.

## 14.4 QuickCheck Alternative

`quickcheck` is another property-based testing framework:

```toml
[dev-dependencies]
quickcheck = "1"
quickcheck_macros = "1"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::quickcheck_macros as quickcheck_macros;
# fn my_encode(data: &[u8]) -> Vec<u8> {
#     data.to_vec()
# }
# fn my_decode(data: &[u8]) -> Result<Vec<u8>, ()> {
#     Ok(data.to_vec())
# }
use quickcheck_macros::quickcheck;

#[quickcheck]
fn sort_is_idempotent(vec: Vec<u32>) -> bool {
    let mut sorted1 = vec.clone();
    sorted1.sort();
    let mut sorted2 = sorted1.clone();
    sorted2.sort();
    sorted1 == sorted2
}

#[quickcheck]
fn decode_encode_roundtrip(data: Vec<u8>) -> bool {
    let encoded = my_encode(&data);
    let decoded = my_decode(&encoded);
    decoded == Ok(data)
}
```

## 14.5 Structured Fuzzing with `cargo-fuzz` and `arbitrary`

```toml
# In fuzz/Cargo.toml
[dependencies]
arbitrary = { version = "1", features = ["derive"] }
```

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate arbitrary;
# extern crate libfuzzer_sys;
# use rust_secure_systems_book::TestServer;
// Define complex input structures
use arbitrary::Arbitrary;

#[derive(Debug, arbitrary::Arbitrary)]
enum FuzzAction {
    Connect { host: String, port: u16 },
    Send { data: Vec<u8> },
    Disconnect,
    Authenticate { username: String, password: Vec<u8> },
}

libfuzzer_sys::fuzz_target!(|actions: Vec<FuzzAction>| {
    let mut server = TestServer::new();
    for action in actions {
        let _ = server.process(action);  // Should never panic
    }
});
```

## 14.6 Summary

- **Property-based testing** (`proptest`, `quickcheck`): Generates random inputs to test invariants. Good for mathematical properties and roundtrip tests.
- **Fuzzing** (`cargo-fuzz`): Coverage-guided input generation. Best for parsers, decoders, and protocol handlers.
- Differential fuzzing is useful when you have a reference implementation, older parser, or wire-compatible rewrite to compare against.
- Fuzz **every** input-processing function, especially network parsers.
- Use structured fuzzing (`arbitrary`) for complex input types.
- Run fuzzing continuously in CI and maintain a seed corpus.
- Use sanitizers (AddressSanitizer, ThreadSanitizer, MemorySanitizer) and Miri alongside fuzzing to detect memory safety and concurrency issues.
- Save and commit regression test cases for all discovered bugs.

In the next chapter, we cover static analysis and code auditing: tools and techniques for finding security issues without executing code.

## 14.7 Exercises

1. **Proptest a Parser**: Write a simple HTTP header parser using `proptest`. Generate valid header strings and verify roundtrip correctness (parse then serialize produces the same string). Generate invalid strings (null bytes, extremely long values, CR/LF injection) and verify they are rejected.

2. **Fuzz Target**: Create a fuzz target for a URL parser. Run `cargo-fuzz` for at least 30 minutes. Examine any crashes or hangs found. Minimize the crashing input, analyze the root cause, fix the bug, and add a regression test.

3. **Custom Arbitrary**: Implement `Arbitrary` for a custom `TlvPacket` struct using the `arbitrary` crate. Write a structured fuzz target that generates semantically valid TLV packets, mutates them, and feeds them to your parser. Compare the coverage achieved with structured vs. unstructured fuzzing.

4. **Sanitizer Pass**: Take a concurrent or FFI-heavy example from Chapters 6, 9, or 10 and run it under ThreadSanitizer or MemorySanitizer on nightly. Record what prerequisites were needed (supported target, instrumented dependencies, clean rebuild, etc.), capture any finding you get, and either fix it or explain why the run was clean.
