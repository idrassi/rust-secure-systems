# Chapter 8 - Cryptography and Secrets Management

> *"Don't roll your own crypto. But if you must, know exactly what you're doing."*

Cryptography is the backbone of secure systems: authentication, encryption, integrity, and key management all depend on it. For security developers, the challenge isn't usually inventing new algorithms; it's using existing ones correctly. Rust's ecosystem provides excellent cryptographic libraries, and the language's safety guarantees eliminate many of the pitfalls that lead to vulnerabilities in C implementations (buffer overflows in crypto code, timing side channels from branches on secret data, etc.).

## 8.1 Choosing Cryptographic Libraries

### 8.1.1 The `ring` Crate

`ring` is the most widely used cryptographic library in Rust. It is a fork of BoringSSL's crypto internals, providing:

- Authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Key agreement (ECDH P-256, X25519)
- Digital signatures (ECDSA P-256, Ed25519, RSA)
- Hashing (SHA-256, SHA-384, SHA-512)
- HMAC
- Constant-time comparisons

Its surface area is intentionally narrower than the full Rust crypto ecosystem. Reach for other reviewed crates when you need features outside that core, such as Argon2 password hashing, misuse-resistant AEADs like AES-GCM-SIV, extended-nonce AEADs like XChaCha20-Poly1305, or newer experimental primitives.

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

fn encrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    
    let mut in_out = plaintext.to_vec();
    let tag = key.seal_in_place_separate_tag(nonce, Aad::from(aad), &mut in_out)
        .unwrap();
    
    // Append authentication tag to ciphertext
    let mut result = in_out;
    result.extend_from_slice(tag.as_ref());
    result
}

fn decrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Option<Vec<u8>> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    
    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext_len = key.open_in_place(nonce, Aad::from(aad), &mut in_out)
        .ok()?
        .len();
    
    Some(in_out[..plaintext_len].to_vec())
}
```

If you are storing or transmitting the result, make the nonce part of the serialized format instead of expecting the caller to remember it out of band. A common layout is `nonce || ciphertext || tag`:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::ring as ring;
# use ring::rand::{SecureRandom, SystemRandom};
fn generate_nonce() -> [u8; 12] {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce).expect("OS CSPRNG failure");
    nonce
}

fn encrypt_for_storage(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce = generate_nonce();
    let ciphertext_and_tag = encrypt(key, &nonce, aad, plaintext);

    let mut packed = nonce.to_vec();
    packed.extend_from_slice(&ciphertext_and_tag);
    packed
}

fn decrypt_from_storage(
    key: &[u8; 32],
    aad: &[u8],
    packed: &[u8],
) -> Option<Vec<u8>> {
    if packed.len() < 12 {
        return None;
    }

    let (nonce_bytes, ciphertext_and_tag) = packed.split_at(12);
    let nonce: [u8; 12] = nonce_bytes.try_into().ok()?;
    decrypt(key, &nonce, aad, ciphertext_and_tag)
}
```

Here, `expect("OS CSPRNG failure")` is intentional: if the operating system cannot provide cryptographic randomness, fail closed instead of continuing with weaker entropy.

Use AAD for metadata that must remain in the clear but still be authenticated: protocol version, content type, sender ID, key ID, or a packet header. If any AAD byte changes, decryption fails even though the bytes were never encrypted.

⚠️ **API note**: `LessSafeKey` is acceptable for focused examples, but it does not enforce nonce sequencing. In production, prefer a `BoundKey` plus a `NonceSequence` when one component owns nonce generation.

⚠️ **Nonce API caveat**: `Nonce::assume_unique_for_key()` does **not** verify uniqueness. It is a promise by the caller to `ring`. Back it with a durable counter, a carefully designed random-nonce scheme, or a nonce-sequence type that centralizes generation.

🔒 **Critical rules for nonce management**:
1. **Never reuse a nonce** with the same key. AES-GCM nonce reuse reveals the XOR of plaintexts and undermines every subsequent use of that key: the attacker can recover the internal GHASH key and make later forgeries trivial. It does **not** directly reveal the AES key, but you should still treat any reuse as a key-compromise event: rotate the key immediately and reject both messages.
2. For random nonces, use a cryptographically secure random number generator and limit to 2^32 encryptions per key.
3. For counter-based nonces, track the counter securely and never reset it.

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

const PBKDF2_ITERATION_COUNT: u32 = 600_000;  // Example baseline only; load and tune this from config in production.
const PBKDF2_ITERATIONS: NonZeroU32 =
    const { NonZeroU32::new(PBKDF2_ITERATION_COUNT).unwrap() };

fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        salt,
        password.as_bytes(),
        &mut key,
    );
    key
}

fn verify_password(password: &str, salt: &[u8], expected: &[u8; 32]) -> bool {
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        salt,
        password.as_bytes(),
        expected,
    ).is_ok()
}
```

🔒 **Security notes**:
- `ring::pbkdf2::verify` uses constant-time comparison internally.
- The `600_000` example matches OWASP's current PBKDF2-HMAC-SHA256 baseline at the time of writing. NIST SP 800-132 is older and more general: it recommends choosing the count as large as acceptable for users, with 1,000 as a historical minimum. Treat iteration counts as a time-sensitive policy knob, not a timeless constant from a book.
- Keeping the typed `NonZeroU32` as a `const` turns an accidental zero into a compile-time failure instead of a panic on first use. The `unwrap()` here executes in the `const` initializer, not at runtime.
- Prefer **Argon2id** for new systems and general password storage.
- Keep **PBKDF2-HMAC-SHA256** for FIPS-constrained environments or legacy interoperability where Argon2id is not an option.
- Use a unique 16+ byte random salt per password.
- Store the algorithm parameters with the password verifier so you can raise the cost over time.
- In real services, load the cost parameter from validated startup configuration instead of baking a book example constant into the binary forever.

For PBKDF2, keep the parameters and verifier together instead of storing loose fields:

```rust
struct StoredPbkdf2Hash {
    iterations: u32,
    salt: Vec<u8>,
    hash: [u8; 32],
}
```

When you raise the PBKDF2 iteration count, keep verifying each password with the parameters stored alongside that user's hash. After a successful login, immediately derive a new hash with the current policy and replace the stored record. This "rehash on login" pattern lets you migrate gradually without breaking existing accounts or silently keeping old work factors forever.

For new password storage, prefer the Argon2 PHC string format shown below because it bundles the algorithm, parameters, salt, and hash into one verifier string.

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

⚠️ **Authentication timing pitfall**: Constant-time byte comparison is not enough if your surrounding control flow still leaks information. If a login path returns immediately for "user not found" but runs Argon2 for "wrong password", an attacker can distinguish the two cases from latency. For username/password authentication, always run the password check against either the real stored hash or a fixed dummy Argon2 hash, then return the same external error in both cases.

🔒 **Argon2 parameters** (per OWASP recommendations):
- **Memory**: 19 MiB (19,456 KiB) minimum
- **Iterations**: 2 time cost (passes) minimum
- **Parallelism**: 1 degree of parallelism minimum
- Adjust upward based on your hardware and acceptable verification latency

⚠️ **Legacy migration note**: bcrypt is still common in deployed systems. Do not choose it for a new design when Argon2id is available, but keep a bcrypt verifier in migration paths so existing password hashes can be checked once and then rehashed to Argon2id after a successful login.

## 8.4 Digital Signatures

### Ed25519 Signatures

Ed25519 is the recommended signature scheme for most applications: it is fast, compact (64-byte signatures, 32-byte public keys), and immune to many side-channel issues that affect ECDSA:

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

### 8.4.1 RSA for Legacy Interoperability

Ed25519 should be your default for new designs, but RSA is still common in X.509 PKI, S/MIME, PGP ecosystems, HSM-backed deployments, and older compliance-driven environments. When you must interoperate with RSA:

- Prefer RSA-PSS for signatures over PKCS#1 v1.5.
- Use at least 2048-bit keys, with 3072-bit keys common for longer-lived deployments.
- Treat RSA as compatibility baggage, not a model for new protocol design.

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
    
    // 2. Key agreement - both parties derive the same shared secret
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
- Use HKDF to derive encryption keys: never use the raw shared secret directly.
- Include context info in HKDF expansion (e.g., `b"encryption-key"`, `b"mac-key"`) to derive different keys for different purposes.

### 8.5.1 Key Rotation and Key Lifetimes

Cryptography often fails operationally, not mathematically. A secure design needs a rotation plan before the first key is deployed:

- **Version every long-lived key** and attach a key ID to ciphertexts, signatures, or wrapped data.
- **Decrypt with old versions, encrypt/sign with the newest version** during rollouts. This "dual-read, single-write" pattern lets you rotate without flag days.
- **Separate key-encryption keys from data/session keys** so most rotations only require re-wrapping smaller keys instead of bulk re-encryption.
- **Define normal lifetime and emergency revocation rules** for each key class: TLS certificates, signing keys, API credentials, master keys, and derived data keys should not all share the same schedule.
- **Rehearse compromised-key response**: how you revoke trust, distribute new keys, invalidate old sessions, and audit which data was exposed.

🔒 **Practical rule**: Session keys should usually be ephemeral and rotated automatically. Long-lived keys should have explicit creation dates, activation windows, retirement windows, and owners.

### 8.5.2 Post-Quantum Readiness

NIST approved its first post-quantum FIPS standards on August 13, 2024: ML-KEM for key establishment, plus ML-DSA and SLH-DSA for signatures. For Rust systems being designed now, the immediate goal is not "replace everything overnight" but "make migration operationally possible."

- **Design for crypto agility**: encode algorithm identifiers, key IDs, version fields, and negotiation rules so you can rotate algorithms without redesigning the protocol.
- **Protect long-lived confidentiality**: if captured traffic must stay secret for many years, evaluate hybrid key establishment that combines a classical component such as X25519 with a post-quantum KEM when your protocol stack supports it.
- **Separate experimentation from deployment**: benchmark size, latency, certificate-chain impact, and interoperability before promoting post-quantum algorithms into production defaults.
- **Use established ecosystems**: for Rust, the `pqcrypto` family and RustCrypto crates such as `ml-kem` and `ml-dsa` are the obvious starting points for evaluation.

⚠️ **Migration rule**: Prefer hybrid and crypto-agile designs during transition periods. Do not invent your own KEM combiner or signature format.

## 8.6 Secrets Management

### 8.6.1 The `zeroize` Crate - Secure Memory Wiping

Cryptographic keys and passwords must be zeroed from memory after use. Rust does not guarantee this by default: variables on the stack or heap may persist until the memory is reused.

```toml
[dependencies]
zeroize = { version = "1", features = ["derive"] }
```

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate zeroize;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
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

🔒 **Critical pattern**: Use `#[derive(Zeroize, ZeroizeOnDrop)]` for types containing secrets. This ensures memory is wiped on ordinary drop paths even if the function exits early (for example via `?`).

⚠️ **Panic strategy caveat**: With `panic = "abort"` from Chapter 2 §2.4, `Drop`-based zeroization still runs on normal returns but does **not** run on panic paths.

⚠️ **Clone caveat**: If a secret type also implements `Clone`, each clone is an independent secret copy with its own lifecycle. Avoid cloning secrets unless you are deliberately zeroizing every copy.

⚠️ **Deserialize caveat**: If a secret-bearing type also implements `serde::Deserialize`, every successful parse creates another live secret instance. Treat deserialization boundaries the same way you treat `Clone`: minimize copies and ensure each instance is dropped on its own lifecycle.

Cancellation in async code does not change this guarantee. As discussed in Chapter 6, aborting a Tokio task works by dropping the future, so `ZeroizeOnDrop` fields are wiped on that drop path too. The exceptions are the usual ones: process aborts, deliberate leaks such as `mem::forget`, or reference cycles that prevent `Drop` from ever running.

One important caveat is shared ownership. If a secret is wrapped in `Arc<T>`, aborting one task only drops that task's clone. The secret is zeroized when the **last** strong reference disappears, not when any individual task is cancelled. Avoid long-lived `Arc` clones of raw secret material unless you are deliberately managing every copy's lifetime.

### 8.6.2 The `secrecy` Crate - Encapsulating Secrets

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

### 8.6.4 Constant-Time Selection and Branching

Constant-time comparison is only part of the story. Secret-dependent branching such as `if secret_bit == 1 { ... }` or `match secret_byte { ... }` can still leak timing information through control flow, cache activity, and branch prediction.

Rust does not make Spectre-style or cache side channels disappear. Constant-time source code still needs review against compiler transformations and the behavior of the target CPU and runtime environment.

For low-level cryptographic code, prefer the `subtle` crate's constant-time building blocks:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::subtle as subtle;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

fn select_mask(secret_bit: u8, limited: u32, full: u32) -> u32 {
    let choice = Choice::from(secret_bit & 1);
    u32::conditional_select(&limited, &full, choice)
}

fn tags_match(provided: &[u8; 32], expected: &[u8; 32]) -> Choice {
    provided.ct_eq(expected)
}
```

`Choice` is intentionally not a normal `bool`; it nudges you toward constant-time APIs instead of accidentally branching on secret material. Use ordinary `if`/`match` only on public values that are already safe to reveal.

⚠️ **Verification note**: Treat constant-time behavior as a property of the compiled code on the targets you actually ship. Source-level review is necessary but not sufficient. Tools such as `dudect` (statistical timing tests) and `ctgrind` (secret-dependent control-flow and memory-access checks) help validate whether a "constant-time" path still behaves that way after optimization on a specific platform.

When benchmarking these paths with `criterion` or ad hoc timing loops, pass both the secret inputs and the observed outputs through `std::hint::black_box`. Otherwise LLVM may fold away work that is present in production and give you a false sense of constant-time behavior.

### 8.6.5 Hardware-Backed and OS-Managed Key Storage

For high-value long-lived keys, keep private-key operations inside a keystore or hardware boundary rather than loading raw key bytes into the application process. Typical options include PKCS#11 devices and HSMs (`cryptoki`), TPM-backed keys (`tss-esapi` over `tpm2-tss`), and OS-managed stores such as DPAPI, Credential Manager, macOS Keychain, Linux keyrings, or Secret Service.

Use these when host compromise, compliance requirements, or signing authority justify the operational cost. Design the application around key handles and operations such as sign, decrypt, or unwrap; avoid exporting the private key unless migration or backup requires it. Chapter 19 returns to the production deployment tradeoffs.

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
    rng.fill(&mut nonce).expect("OS CSPRNG failure");
    nonce
}

fn generate_api_token() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("OS CSPRNG failure");
    hex::encode(bytes)
}
```

⚠️ **Prefer** `ring::rand::SystemRandom` for all cryptographic purposes in production: it is explicit, auditable, and always backed by the OS CSPRNG. In `rand` 0.8, `thread_rng()` is also backed by a CSPRNG, but `SystemRandom` makes the security intent clearer and keeps key generation tied directly to the operating system RNG.

In small examples, panicking on `rng.fill(...)` is acceptable because the only sensible response to OS CSPRNG failure is to abort or surface the error, never to keep running with a weaker fallback.

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

**Revocation note**: `with_root_certificates(...)` loads trust anchors, but it does not configure a CRL or OCSP policy by itself. If certificate revocation matters in your environment, add an explicit verifier configuration or terminate TLS in infrastructure that enforces revocation; short-lived certificates are usually easier to operate than revocation-by-default for ordinary service fleets, but they are not a substitute for revocation in high-assurance environments where one compromised key could unlock a fleet or a critical trust domain.

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

### 8.8.2 Token-Based Authentication: JWT and PASETO

Bearer tokens are common for API authentication, but verification must be stricter than "the library decoded it successfully."

- **Pin the algorithm in configuration** and reject tokens whose header does not match it. Never let the token choose the verification algorithm.
- **Verify the signature first**, then validate claims such as `exp`, `nbf`, `iss`, `aud`, and any application-specific scope or tenant claims.
- **Keep expirations short** and rotate signing keys with explicit `kid` values. Reject unknown key IDs instead of falling back to a default key.
- **Treat claims as authorization input only after issuer and audience validation succeeds**.

If you need JWT ecosystem interoperability, crates such as `jsonwebtoken` are common choices. If you control both ends of the protocol and do not need JWT compatibility, PASETO crates such as `pasetors` reduce some historical footguns by making algorithm choices less header-driven.

⚠️ **Do not** accept `alg: none`, mix symmetric and asymmetric algorithms for the same issuer, or trust unsigned header fields to select keys or verification behavior.

## 8.9 Common Cryptographic Mistakes (and How Rust Helps)

| Mistake | C/C++ Consequence | Rust Prevention |
|---------|-------------------|-----------------|
| Nonce reuse | Catastrophic (GCM) | API design can make nonce ownership explicit; `BoundKey` + `NonceSequence` helps |
| Missing auth | Padding oracle | `ring` API requires AEAD |
| Timing leak | Side-channel | `ring::constant_time` module |
| Key not zeroed | Memory disclosure | `zeroize` crate with `ZeroizeOnDrop` |
| Weak RNG | Predictable keys | `SystemRandom` is always a CSPRNG |
| Hardcoded keys | Source code leak | Use `Secret<T>`, env variables, or vaults |

## 8.10 Summary

- Use `ring` or well-audited RustCrypto crates: never implement crypto primitives yourself.
- Always use **authenticated encryption** (AES-GCM, ChaCha20-Poly1305).
- Use AAD to authenticate unencrypted headers and protocol metadata.
- **Never reuse nonces** with the same key for AEAD ciphers.
- Prefer nonce-misuse-resistant AEADs such as AES-GCM-SIV or XChaCha20-Poly1305 when nonce coordination is operationally hard.
- Derive keys from passwords using Argon2id (preferred) or PBKDF2 with proper parameters and salts.
- Use Ed25519 for digital signatures; use X25519 + HKDF for key exchange.
- Plan key rotation and emergency revocation up front; cryptographic agility is an operational requirement.
- Use `zeroize` to wipe secrets from memory; use `secrecy` to encapsulate them.
- Use hardware-backed or OS-managed keystores for high-value long-lived keys.
- Always use constant-time comparison for secrets.
- Plan post-quantum migration now for long-lived systems, and prefer hybrid transitions over abrupt algorithm replacement.
- Use `rustls` for TLS instead of OpenSSL.
- Use certificate pinning only as an additional control for a narrow set of internal endpoints.
- Treat token verification as cryptography plus policy: pin algorithms, verify signatures, and validate claims.
- Use `SystemRandom` for all cryptographic random number generation.

In the next chapter, we enter the world of `unsafe` Rustwhere the compiler's safety guarantees are manually maintained.

## 8.11 Exercises

1. **Encrypt/Decrypt Roundtrip**: Using `ring`, implement AES-256-GCM encryption and decryption with proper nonce management. Use a counter-based nonce scheme. Write tests for: successful roundtrip, tampered ciphertext (should fail), wrong key (should fail), and replayed nonce (demonstrate that nonce reuse leaks the XOR of plaintexts and explain why real AES-GCM reuse also breaks authentication).

2. **Key Derivation Pipeline**: Implement a password-based key derivation pipeline: generate a random salt, derive a 256-bit key using PBKDF2 with 600,000 iterations, encrypt a message, then decrypt and verify. Store only the salt and ciphertext. Ensure the key is zeroized after use with the `zeroize` crate.

3. **Constant-Time Comparison Test**: Write two comparison functions: one using `==` on byte slices and one using `ring::constant_time::verify_slices_are_equal`. Benchmark both with timing measurements and demonstrate that the standard comparison leaks timing information on the position of the first differing byte. (Use `criterion` for statistically sound benchmarking.)

4. **TLS Server**: Using `rustls` and `tokio-rustls`, create a minimal TLS server that accepts a single connection, reads a message, and echoes it back. Use self-signed certificates generated with the `rcgen` crate. Test with `openssl s_client` to verify the connection.

5. **Argon2 Password Hasher**: Implement a user registration and login flow using Argon2id. Store the PHC-format hash string (which includes salt and parameters). Verify that: (a) correct passwords succeed, (b) wrong passwords fail, (c) the hash string reveals no information about the password, (d) verification takes approximately the same time for valid and invalid users.

6. **Key Exchange Simulation**: Implement the X25519 → HKDF → AES-256-GCM pipeline for two parties (Alice and Bob). Verify that: (a) both derive the same encryption key, (b) Alice can encrypt a message that Bob decrypts, (c) using a different key pair produces a different shared secret (forward secrecy), (d) tampering with a ciphertext causes decryption to fail.

7. **Rotation and Pinning Plan**: Design a key-management plan for an internal service. Define which keys are ephemeral, which are long-lived, how key IDs are encoded, how "decrypt old / encrypt new" rollout works, how compromised keys are revoked, and how an SPKI pin set with at least one backup pin is distributed to clients.
