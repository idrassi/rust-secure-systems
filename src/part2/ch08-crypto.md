# Chapter 8 — Cryptography and Secrets Management

> *"Don't roll your own crypto. But if you must, know exactly what you're doing."*

Cryptography is the backbone of secure systems—authentication, encryption, integrity, and key management all depend on it. For security developers, the challenge isn't usually inventing new algorithms; it's using existing ones correctly. Rust's ecosystem provides excellent cryptographic libraries, and the language's safety guarantees eliminate many of the pitfalls that lead to vulnerabilities in C implementations (buffer overflows in crypto code, timing side channels from branches on secret data, etc.).

## 8.1 Choosing Cryptographic Libraries

### 8.1.1 The `ring` Crate

`ring` is the most widely used cryptographic library in Rust. It is a fork of BoringSSL's crypto internals, providing:

- Authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Key agreement (ECDH P-256, X25519)
- Digital signatures (ECDSA P-256, Ed25519, RSA)
- Hashing (SHA-256, SHA-384, SHA-512)
- HMAC
- Constant-time comparisons

```toml
# Cargo.toml
[dependencies]
ring = "0.17"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ring as ring;
use ring::{
    aead::{self, BoundKey, Nonce, NonceSequence},
    digest,
    hmac::{self, Key},
};

// SHA-256 hash
fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = digest::digest(&digest::SHA256, data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

// HMAC-SHA256
fn hmac_sha256(key: &[u8], message: &[u8]) -> hmac::Tag {
    let key = Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, message)
}
```

### 8.1.2 The `RustCrypto` Ecosystem

The RustCrypto project provides pure-Rust implementations:

```toml
[dependencies]
sha2 = "0.10"
aes-gcm = "0.10"
ed25519-dalek = { version = "2", features = ["zeroize"] }
x25519-dalek = { version = "2", features = ["zeroize"] }
```

🔒 **Recommendation**: Use `ring` for production cryptographic operations (audited, widely deployed). Use RustCrypto crates when you need pure-Rust implementations (no C dependencies, easier cross-compilation).

## 8.2 Authenticated Encryption

**Always use authenticated encryption.** Never use encryption without authentication (e.g., AES-CBC without HMAC). This prevents chosen-ciphertext attacks and padding oracle attacks.

### AES-256-GCM with ring

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ring as ring;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

fn encrypt(key: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    
    let mut in_out = plaintext.to_vec();
    let tag = key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
        .unwrap();
    
    // Append authentication tag to ciphertext
    let mut result = in_out;
    result.extend_from_slice(tag.as_ref());
    result
}

fn decrypt(key: &[u8; 32], nonce_bytes: &[u8; 12], ciphertext_and_tag: &[u8]) -> Option<Vec<u8>> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    
    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext_len = key.open_in_place(nonce, Aad::empty(), &mut in_out)
        .ok()?
        .len();
    
    Some(in_out[..plaintext_len].to_vec())
}
```

🔒 **Critical rules for nonce management**:
1. **Never reuse a nonce** with the same key. AES-GCM nonce reuse reveals the XOR of plaintexts and leaks the authentication key.
2. For random nonces, use a cryptographically secure random number generator and limit to 2^32 encryptions per key.
3. For counter-based nonces, track the counter securely and never reset it.

More precisely: nonce reuse in AES-GCM reveals the XOR of plaintexts and leaks the GHASH authentication subkey, which enables message forgery. It does **not** directly reveal the AES key, but it is still catastrophic.

### ChaCha20-Poly1305 (Alternative to AES-GCM)

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ring as ring;
use ring::aead::{UnboundKey, CHACHA20_POLY1305};

fn create_chacha20_key(key_bytes: &[u8; 32]) -> UnboundKey {
    UnboundKey::new(&CHACHA20_POLY1305, key_bytes).unwrap()
}
```

🔒 **When to prefer ChaCha20-Poly1305**: On platforms without AES hardware acceleration, ChaCha20 is faster and constant-time. On modern x86/ARM with AES-NI, AES-GCM is typically faster.

### Nonce-Misuse-Resistant Alternatives

If your system cannot reliably guarantee nonce uniqueness across crashes, replicas, offline clients, or multi-writer deployments, prefer an AEAD that degrades more safely under nonce mistakes:

```toml
[dependencies]
aes-gcm-siv = "0.11"
chacha20poly1305 = "0.10"
```

- **AES-GCM-SIV** (RFC 8452) is a misuse-resistant variant of GCM. Accidental nonce reuse is still a bug, but it is much less catastrophic than nonce reuse in classic AES-GCM.
- **XChaCha20-Poly1305** extends the nonce to 192 bits (24 bytes), which makes random-nonce designs much easier to operate safely in distributed systems and local-encryption tools.
- `ring` does not currently expose these constructions, so use well-reviewed RustCrypto crates when you need them.

🔒 **Design guidance**:
- If you need an AES-based construction and are worried about occasional nonce duplication, consider AES-GCM-SIV.
- If random nonces are operationally simpler than durable counters, XChaCha20-Poly1305 is often the easiest safe choice.
- Misuse resistance is not permission to reuse nonces deliberately. You still need uniqueness, replay handling, and a clear key lifecycle.

## 8.3 Key Derivation

Never use passwords directly as encryption keys. Use a key derivation function (KDF):

### HKDF (for deriving keys from a shared secret)

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ring as ring;
use ring::hkdf::{Salt, HKDF_SHA256};

/// A helper type that tells `ring` how many bytes of key material to produce.
struct KeyBytes;

impl ring::hkdf::KeyType for KeyBytes {
    fn len(&self) -> usize {
        32
    }
}

fn derive_key(secret: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(secret);
    
    let mut key = [0u8; 32];
    let binding = [info];
    let okm = prk.expand(&binding, KeyBytes).unwrap();
    okm.fill(&mut key).unwrap();
    key
}
```

### PBKDF2 or Argon2 (for deriving keys from passwords)

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ring as ring;
use ring::pbkdf2;
use std::num::NonZeroU32;

const PBKDF2_ITERATIONS: u32 = 600_000;  // Example baseline only; re-benchmark before release.

fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );
    key
}

fn verify_password(password: &str, salt: &[u8], expected: &[u8; 32]) -> bool {
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        expected,
    ).is_ok()
}
```

🔒 **Security notes**:
- `ring::pbkdf2::verify` uses constant-time comparison internally.
- Treat PBKDF2 iteration counts as a time-sensitive policy knob, not a timeless constant from a book. Benchmark on your hardware and compare against current OWASP and NIST guidance before release.
- Prefer Argon2id over PBKDF2 for new systems (use the `argon2` crate).
- Use a unique 16+ byte random salt per password.
- Store the algorithm parameters with the password verifier so you can raise the cost over time.

### Argon2id (Recommended for Password Hashing)

Argon2 is the winner of the 2015 Password Hashing Competition and is recommended by OWASP over PBKDF2 because it is resistant to GPU/ASIC attacks:

```toml
[dependencies]
argon2 = "0.5"
password-hash = { version = "0.5", features = ["std"] }
rand_core = { version = "0.6", features = ["std"] }
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::argon2 as argon2;
# use rust_secure_systems_book::deps::password_hash as password_hash;
# use rust_secure_systems_book::deps::rand_core as rand_core;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;

fn hash_password(password: &str) -> Result<String, password_hash::errors::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}
```

🔒 **Argon2 parameters** (per OWASP recommendations):
- **Memory**: 19 MiB (19,456 KiB) minimum
- **Iterations**: 2 time cost (passes) minimum
- **Parallelism**: 1 degree of parallelism minimum
- Adjust upward based on your hardware and acceptable verification latency

## 8.4 Digital Signatures

### Ed25519 Signatures

Ed25519 is the recommended signature scheme for most applications — it is fast, compact (64-byte signatures, 32-byte public keys), and immune to many side-channel issues that affect ECDSA:

```toml
[dependencies]
ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }
rand = "0.8"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ed25519_dalek as ed25519_dalek;
# use rust_secure_systems_book::deps::rand as rand;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::rngs::OsRng;

fn sign_example() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    let message = b"important document";
    
    // Sign
    let signature: Signature = signing_key.sign(message);
    
    // Verify
    assert!(verifying_key.verify(message, &signature).is_ok());
    
    // Tampered message fails verification
    assert!(verifying_key.verify(b"tampered document", &signature).is_err());
}
```

`SigningKey::generate` is only available when the crate's `rand_core` feature is enabled, so make sure your dependency configuration includes it.

🔒 **Security notes**:
- Ed25519 uses deterministic signatures (no per-signature randomness needed), eliminating the catastrophic nonce-reuse vulnerability that affects ECDSA.
- Always verify signatures before trusting signed data.

## 8.5 Key Exchange

### X25519 → HKDF → AEAD Pipeline

The standard pattern for establishing a shared secret and encrypting data is: X25519 key agreement, HKDF key derivation, then AEAD encryption:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::rand as rand;
# use rust_secure_systems_book::deps::ring as ring;
use ring::{
    agreement::{self, UnparsedPublicKey, X25519},
    hkdf::{Salt, HKDF_SHA256},
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
};

fn key_exchange_pipeline() {
    // 1. Each party generates an ephemeral key pair
    let rng = ring::rand::SystemRandom::new();
    let alice_private = agreement::EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let alice_public = alice_private.compute_public_key().unwrap();
    
    let bob_private = agreement::EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let bob_public = bob_private.compute_public_key().unwrap();
    
    // 2. Key agreement — both parties derive the same shared secret
    let alice_shared = agreement::agree_ephemeral(
        alice_private,
        &UnparsedPublicKey::new(&X25519, bob_public.as_ref()),
        |shared_secret| {
            // 3. Derive encryption key from shared secret using HKDF
            let salt = Salt::new(HKDF_SHA256, b"session-salt");
            let prk = salt.extract(shared_secret);
            
            struct KeyLen;
            impl ring::hkdf::KeyType for KeyLen {
                fn len(&self) -> usize { 32 }
            }
            
            let mut key_bytes = [0u8; 32];
            prk.expand(&[b"encryption-key"], KeyLen).unwrap().fill(&mut key_bytes).unwrap();
            key_bytes
        },
    ).unwrap();
    
    // 4. Encrypt with the derived key
    let unbound_key = UnboundKey::new(&AES_256_GCM, &alice_shared).unwrap();
    let key = LessSafeKey::new(unbound_key);
    // ... use key.seal_in_place_separate_tag / open_in_place
}
```

🔒 **Key exchange security**:
- Always use **ephemeral** key pairs (generate fresh per session) for forward secrecy.
- Use HKDF to derive encryption keys — never use the raw shared secret directly.
- Include context info in HKDF expansion (e.g., `b"encryption-key"`, `b"mac-key"`) to derive different keys for different purposes.

### 8.5.1 Key Rotation and Key Lifetimes

Cryptography often fails operationally, not mathematically. A secure design needs a rotation plan before the first key is deployed:

- **Version every long-lived key** and attach a key ID to ciphertexts, signatures, or wrapped data.
- **Decrypt with old versions, encrypt/sign with the newest version** during rollouts. This "dual-read, single-write" pattern lets you rotate without flag days.
- **Separate key-encryption keys from data/session keys** so most rotations only require re-wrapping smaller keys instead of bulk re-encryption.
- **Define normal lifetime and emergency revocation rules** for each key class: TLS certificates, signing keys, API credentials, master keys, and derived data keys should not all share the same schedule.
- **Rehearse compromised-key response**: how you revoke trust, distribute new keys, invalidate old sessions, and audit which data was exposed.

🔒 **Practical rule**: Session keys should usually be ephemeral and rotated automatically. Long-lived keys should have explicit creation dates, activation windows, retirement windows, and owners.

## 8.6 Secrets Management

### 8.6.1 The `zeroize` Crate — Secure Memory Wiping

Cryptographic keys and passwords must be zeroed from memory after use. Rust does not guarantee this by default—variables on the stack or heap may persist until the memory is reused.

```toml
[dependencies]
zeroize = { version = "1", features = ["derive"] }
```

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate zeroize;
use zeroize::Zeroize;

#[derive(zeroize::Zeroize)]
#[zeroize(drop)]  // Automatically zeroize on Drop
struct SecretKey {
    key: [u8; 32],
    nonce: [u8; 12],
}

fn use_key() {
    let key = SecretKey {
        key: [0xAB; 32],
        nonce: [0x00; 12],
    };
    
    // Use key...
    
    // When `key` goes out of scope, it is automatically zeroed
    // The memory will contain all zeros before being freed
}
```

🔒 **Critical pattern**: Always use `#[zeroize(drop)]` for types containing secrets. This ensures memory is wiped even if the function exits early (e.g., via `?` operator).

### 8.6.2 The `secrecy` Crate — Encapsulating Secrets

```toml
[dependencies]
secrecy = "0.10"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::secrecy as secrecy;
use secrecy::{ExposeSecret, SecretString};

# struct Session;
# impl Session {
#     fn new() -> Self {
#         Self
#     }
# }
# #[derive(Debug)]
# struct AuthError;

fn authenticate(password: SecretString) -> Result<Session, AuthError> {
    // The password cannot be accidentally logged, printed, or serialized
    // It can only be accessed via expose_secret()
    
    let pw_bytes = password.expose_secret().as_bytes();
    // ... verify password
    
    // This would not compile:
    // println!("Password: {}", password);  // SecretString doesn't impl Display
    // log::info!("Trying {}", password);   // Doesn't impl Debug either
    
    Ok(Session::new())
}
```

🔒 **Security pattern**: `Secret<T>` prevents secrets from being accidentally:
- Printed to logs (no `Debug`/`Display`)
- Serialized (no `Serialize`)
- Exposed without an explicit `ExposeSecret` call, which makes secret-handling sites easier to audit

`secrecy` helps prevent accidental disclosure, but it does **not** make comparisons constant-time by itself. When comparing secrets, use an API that explicitly documents constant-time behavior.

### 8.6.3 Constant-Time Comparison

Comparing secrets (passwords, MACs, tokens) with normal equality operators leaks timing information:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ring as ring;
use ring::constant_time::verify_slices_are_equal;

fn verify_token(provided: &[u8], expected: &[u8]) -> bool {
    verify_slices_are_equal(provided, expected).is_ok()
}
```

🔒 **Security impact**: Prevents timing side-channel attacks (CWE-208). A normal `==` comparison returns `false` as soon as it finds a mismatching byte, leaking information about which bytes match.

## 8.7 Random Number Generation

Use cryptographically secure random number generators (CSPRNGs) for all security-sensitive operations:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::hex as hex;
# use rust_secure_systems_book::deps::ring as ring;
use ring::rand::{SecureRandom, SystemRandom};

fn generate_nonce() -> [u8; 12] {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce).unwrap();
    nonce
}

fn generate_api_token() -> String {
    use ring::rand::SecureRandom;
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).unwrap();
    hex::encode(bytes)
}
```

⚠️ **Prefer** `ring::rand::SystemRandom` for all cryptographic purposes in production — it is explicit, auditable, and always backed by the OS CSPRNG. In `rand` 0.8, `thread_rng()` is also backed by a CSPRNG, but `SystemRandom` makes the security intent clearer and keeps key generation tied directly to the operating system RNG.

## 8.8 TLS with rustls

For secure network communication, use `rustls` instead of OpenSSL:

```toml
[dependencies]
rustls = "0.23"
tokio-rustls = "0.26"
webpki-roots = "0.26"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::rustls as rustls;
# use rust_secure_systems_book::deps::webpki_roots as webpki_roots;
use rustls::{ClientConfig, RootCertStore};
use webpki_roots::TLS_SERVER_ROOTS;

fn create_tls_client_config() -> ClientConfig {
    let mut root_certs = RootCertStore::empty();
    root_certs.extend(TLS_SERVER_ROOTS.iter().cloned());
    
    ClientConfig::builder()
        .with_root_certificates(root_certs)
        .with_no_client_auth()
}
```

### 8.8.1 Certificate Pinning for Internal Services

For private APIs, control planes, and service-to-service calls, CA validation alone may be too broad. Certificate pinning adds an application-controlled trust decision on top of normal PKI validation:

- Prefer pinning a **public key** (for example, the SPKI hash), not an entire leaf certificate, so routine certificate renewal does not force an outage.
- Maintain at least one **backup pin** before deployment. Pinning without a backup is an outage plan, not a security plan.
- Keep **hostname and chain validation enabled**. Pinning complements PKI; it does not replace it.
- Use pinning for a **small, known set of internal endpoints**. Do not apply hardcoded pins to arbitrary public websites or general-purpose clients.

With `rustls`, the usual pattern is to keep the normal verifier and add one more check that compares the validated peer certificate's public key against an out-of-band allowlist. Avoid "dangerous" configurations that disable certificate verification entirely.

🔒 **Why rustls over OpenSSL**:
- Memory-safe implementation (no buffer overflows in TLS parsing)
- No unsafe code in the TLS state machine
- Simpler API reduces misuse risk
- Active security auditing

## 8.9 Common Cryptographic Mistakes (and How Rust Helps)

| Mistake | C/C++ Consequence | Rust Prevention |
|---------|-------------------|-----------------|
| Nonce reuse | Catastrophic (GCM) | Type system can enforce nonce tracking |
| Missing auth | Padding oracle | `ring` API requires AEAD |
| Timing leak | Side-channel | `ring::constant_time` module |
| Key not zeroed | Memory disclosure | `zeroize` crate with `#[zeroize(drop)]` |
| Weak RNG | Predictable keys | `SystemRandom` is always a CSPRNG |
| Hardcoded keys | Source code leak | Use `Secret<T>`, env variables, or vaults |

## 8.10 Summary

- Use `ring` or well-audited RustCrypto crates—never implement crypto primitives yourself.
- Always use **authenticated encryption** (AES-GCM, ChaCha20-Poly1305).
- **Never reuse nonces** with the same key for AEAD ciphers.
- Prefer nonce-misuse-resistant AEADs such as AES-GCM-SIV or XChaCha20-Poly1305 when nonce coordination is operationally hard.
- Derive keys from passwords using Argon2id (preferred) or PBKDF2 with proper parameters and salts.
- Use Ed25519 for digital signatures; use X25519 + HKDF for key exchange.
- Plan key rotation and emergency revocation up front; cryptographic agility is an operational requirement.
- Use `zeroize` to wipe secrets from memory; use `secrecy` to encapsulate them.
- Always use constant-time comparison for secrets.
- Use `rustls` for TLS instead of OpenSSL.
- Use certificate pinning only as an additional control for a narrow set of internal endpoints.
- Use `SystemRandom` for all cryptographic random number generation.

In the next chapter, we enter the world of `unsafe` Rust—where the compiler's safety guarantees are manually maintained.

## 8.11 Exercises

1. **Encrypt/Decrypt Roundtrip**: Using `ring`, implement AES-256-GCM encryption and decryption with proper nonce management. Use a counter-based nonce scheme. Write tests for: successful roundtrip, tampered ciphertext (should fail), wrong key (should fail), and replayed nonce (demonstrate the danger by showing the XOR of two plaintexts is revealed).

2. **Key Derivation Pipeline**: Implement a password-based key derivation pipeline: generate a random salt, derive a 256-bit key using PBKDF2 with 600,000 iterations, encrypt a message, then decrypt and verify. Store only the salt and ciphertext. Ensure the key is zeroized after use with the `zeroize` crate.

3. **Constant-Time Comparison Test**: Write two comparison functions: one using `==` on byte slices and one using `ring::constant_time::verify_slices_are_equal`. Benchmark both with timing measurements and demonstrate that the standard comparison leaks timing information on the position of the first differing byte. (Use `criterion` for statistically sound benchmarking.)

4. **TLS Server**: Using `rustls` and `tokio-rustls`, create a minimal TLS server that accepts a single connection, reads a message, and echoes it back. Use self-signed certificates generated with the `rcgen` crate. Test with `openssl s_client` to verify the connection.

5. **Argon2 Password Hasher**: Implement a user registration and login flow using Argon2id. Store the PHC-format hash string (which includes salt and parameters). Verify that: (a) correct passwords succeed, (b) wrong passwords fail, (c) the hash string reveals no information about the password, (d) verification takes approximately the same time for valid and invalid users.

6. **Key Exchange Simulation**: Implement the X25519 → HKDF → AES-256-GCM pipeline for two parties (Alice and Bob). Verify that: (a) both derive the same encryption key, (b) Alice can encrypt a message that Bob decrypts, (c) using a different key pair produces a different shared secret (forward secrecy), (d) tampering with a ciphertext causes decryption to fail.

7. **Rotation and Pinning Plan**: Design a key-management plan for an internal service. Define which keys are ephemeral, which are long-lived, how key IDs are encoded, how "decrypt old / encrypt new" rollout works, how compromised keys are revoked, and how an SPKI pin set with at least one backup pin is distributed to clients.
