# Chapter 1 - Why Rust for Secure Systems

> *"The best way to write secure code is to make insecure code impossible to write."*

## 1.1 The Memory Safety Crisis

For over three decades, the systems programming world has relied on C and C++. These languages offer unparalleled control over hardware and memory, but that control comes at a steep security cost. Consider the data:

- **Google's Chrome team** reported that over 70% of high-severity security bugs were memory safety issues (use-after-free, buffer overflows, etc.).
- **Microsoft** found that approximately 70% of vulnerabilities in their products over a decade were due to memory safety bugs.
- The **U.S. NSA, CISA, and FBI** jointly recommended moving away from C/C++ to memory-safe languages.

The common vulnerability classes in C/C++ systems code include:

| CWE | Name | Description |
|-----|------|-------------|
| CWE-119 | Buffer Overflow | Writing beyond allocated memory bounds |
| CWE-416 | Use-After-Free | Accessing memory after it has been freed |
| CWE-476 | NULL Pointer Dereference | Dereferencing a null pointer |
| CWE-787 | Out-of-Bounds Write | Writing past the end of an array |
| CWE-125 | Out-of-Bounds Read | Reading past the end of an array |
| CWE-190 | Integer Overflow | Arithmetic overflow leading to incorrect behavior |
| CWE-362 | Concurrent Race Condition | Unsynchronized shared-state access between threads |
| CWE-367 | TOCTOU Race Condition | Time-of-check/time-of-use mismatch between validation and use |

`CWE-367` is a more specific child of the broader `CWE-362` race-condition family. We list it separately because TOCTOU deserves its own design discussion in secure systems code.

These are not theoretical risks. They are the most exploited vulnerability classes in real-world attacks, enabling remote code execution, privilege escalation, and data theft.

## 1.2 What Makes Rust Different

Rust addresses these problems through three pillars:

### 1.2.1 Ownership and Borrowing

Every value in Rust has a single *owner*. When the owner goes out of scope, the value is automatically deallocated. References to values are governed by strict rules:

- You can have **either** one mutable reference **or** any number of immutable references, but not both at the same time.
- References must always be valid (no dangling pointers).

This is enforced at compile time by the **borrow checker**:

```rust,compile_fail
// This code demonstrates a compile error:
fn main() {
    let mut data = vec![1, 2, 3];

    let first = &data[0];     // immutable borrow
    data.push(4);             // ERROR: cannot mutate while borrowed
    println!("{}", first);    // `first` is still in use
}
```

The compiler rejects this code. In C, this would be a potential use-after-free if `push` caused a reallocation. In Rust, it simply does not compile.

🔒 **Security impact**: Eliminates CWE-119, CWE-416, CWE-787, and CWE-125 at compile time for safe Rust code. NULL dereference prevention comes from the type system (`Option<T>`), not ownership alone.

### 1.2.2 Type System

Rust's type system is rich and expressive. It uses:

- **Algebraic data types** (`enum` and `struct`) that make illegal states unrepresentable.
- **Pattern matching** that is exhaustive, the compiler ensures all cases are handled.
- **No implicit nulls**, the `Option<T>` type explicitly represents the presence or absence of a value.
- **No implicit conversions**, you must be explicit about type changes.

```rust
#[derive(Debug)]
struct User {
    name: &'static str,
}

// No null pointers. Use Option instead.
fn find_user(id: u32) -> Option<User> {
    match id {
        42 => Some(User { name: "admin" }),
        _ => None,
    }
}

fn main() {
    match find_user(42) {
        Some(user) => println!("Found: {}", user.name),
        None => println!("User not found"),
    }
}
```

🔒 **Security impact**: Eliminates CWE-476 (NULL deref) by replacing null with `Option<T>`. Helps eliminate CWE-190 (integer overflow): debug builds panic on overflow by default, and release builds do so when `overflow-checks = true` is enabled as recommended in Chapter 2.

### 1.2.3 Fearless Concurrency

Rust's ownership model extends to concurrency. The type system enforces that:

- Data races are impossible in safe Rust code.
- Thread safety is verified at compile time via `Send` and `Sync` traits.
- Shared state requires explicit synchronization (`Mutex`, `RwLock`, atomics).

```rust
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            let mut num = counter.lock().unwrap();
            *num += 1;
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
    println!("Result: {}", *counter.lock().unwrap());
}
```

🔒 **Security impact**: Eliminates unsynchronized data races (CWE-362) in safe Rust code. It does **not** eliminate higher-level race conditions such as TOCTOU (CWE-367).

## 1.3 What Rust Does NOT Protect Against

Honesty is important. Rust is not a complete security solution:

| Threat Category | Rust Protects? |
|----------------|----------------|
| Memory safety bugs | ✅ Yes (in safe code) |
| Data races | ✅ Yes (in safe code) |
| Race conditions / TOCTOU | ❌ No |
| NULL dereferences | ✅ Yes (in safe code) |
| Logic errors | ❌ No |
| Integer overflow (release) | ⚠️ Wraps by default; use checked arithmetic |
| Side-channel attacks | ❌ No |
| Incorrect crypto usage | ❌ No (but APIs can guide you) |
| Social engineering | ❌ No |
| `unsafe` code bugs | ⚠️ Not automatically; requires review |

The `unsafe` keyword is Rust's escape hatch. It allows you to bypass the compiler's safety checks for:

- Dereferencing raw pointers
- Calling unsafe functions (including FFI)
- Accessing or modifying mutable statics
- Accessing fields of unions
- Implementing unsafe traits

⚠️ **Critical rule**: All `unsafe` code must be audited manually. We dedicate Chapter 9 to this topic.

## 1.4 Rust in the Security Ecosystem

Rust is increasingly adopted in security-critical domains:

- **Operating systems**: Linux kernel modules (since 2022), Windows kernel components, Android (Google)
- **Web browsers**: Firefox (Servo/Quantum), Chrome components
- **Networking**: Cloudflare's pingora, Linkerd service mesh
- **Cryptography**: The `ring` crate, TLS implementations
- **Embedded**: TrustZone TAs, secure bootloaders
- **Tooling**: Password managers, VPN clients, endpoint security agents
- **High assurance**: Formal-verification tools such as Kani and Prusti for bounded proofs and contracts (see Chapter 15)

## 1.5 Comparison with Other "Safe" Languages

| Feature | Rust | C/C++ | Go | Java/C# |
|---------|------|-------|----|---------|
| Memory safety | Compile-time | No | GC | GC |
| No GC overhead | ✅ | ✅ | ❌ | ❌ |
| Zero-cost abstractions | ✅ | Manual | Partial | ❌ |
| Compile-time data race freedom | ✅ | ❌ | ❌ | Runtime primitives only |
| Systems-level control | ✅ | ✅ | Partial | ❌ |
| Predictable performance | ✅ | ✅ | With GC pauses | ❌ |
| FFI to C | ✅ | N/A | ✅ | ✅ |
| Deterministic destruction | ✅ | Manual | ❌ | ❌ |

Go provides memory safety through garbage collection, but it does not prevent data races between goroutines at compile time. Go's race detector is useful, but it is a runtime tool rather than a compile-time guarantee. Java and C# provide locks, atomics, and memory-model guarantees, but they do not provide compile-time race prevention. Only Rust provides both memory safety and compile-time data race freedom without runtime GC overhead.

## 1.6 Summary

- Rust eliminates the most prevalent vulnerability classes (memory safety bugs) at compile time.
- The ownership model, type system, and concurrency guarantees work together to make insecure patterns impossible to express in safe code.
- Rust does not protect against logic errors, side channels, or misuse of `unsafe` code, defense in depth is still required.
- Rust is being adopted across the security industry for critical infrastructure.

In the next chapter, we will set up a development environment optimized for secure Rust development, including tooling for linting, formatting, and dependency auditing.

## 1.7 Exercises

1. **CVE Analysis**: Choose a recent memory-safety CVE from a C/C++ project (e.g., from [cve.org](https://www.cve.org)). Identify the CWE classification. Write a short explanation of how Rust's ownership model, type system, or borrow checker would have prevented it at compile time.

2. **Threat Model Table**: For a network-facing daemon you maintain or have worked on, create a threat model table like the one in §1.3. For each row, note whether Rust's safe code would eliminate that class, and what additional mitigations would still be needed.

3. **Unsafe Audit Scope**: Install `cargo geiger` on a Rust project (or a public crate). Run `cargo geiger` and identify which dependencies use `unsafe`. For each one, note whether the `unsafe` usage is expected (e.g., cryptography, FFI) or surprising.
