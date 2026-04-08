# Foreword

<section class="book-masthead">
  <p class="book-masthead__eyebrow">Rust for Secure Systems Programming</p>
  <p class="book-masthead__author">By <strong>Mounir IDRASSI</strong></p>
  <p class="book-masthead__meta">Book version 1.0.6 | April 8, 2026 | <a href="https://amcrypto.jp">amcrypto.jp</a></p>
</section>

If you are reading this book, you likely already know the landscape: buffer overflows, use-after-free bugs, integer overflows, race conditions, and injection flaws remain the dominant vulnerability classes in systems software. Despite decades of effort(static analyzers, sanitizers, coding standards, and security review), C and C++ codebases continue to produce critical vulnerabilities at an alarming rate. The fundamental problem is that C and C++ give the programmer *too much power* with *too little guidance*.

Rust changes the equation.

Rust is not a silver bullet, but it is the most significant advance in systems programming language design for secure coding in decades. Its ownership model, borrow checker, and type system work together to eliminate entire categories of memory safety and concurrency bugs *at compile time*, without requiring a garbage collector or runtime overhead. This is a paradigm shift: instead of finding bugs through testing and review, Rust prevents them from existing in the first place.

## Who This Book Is For

This book is written for **system developers who specialize in secure coding**. You likely have experience with:

- C or C++ systems programming (kernel modules, daemons, network services, embedded firmware)
- Secure development lifecycles (SDL), threat modeling, and code review
- Vulnerability classes defined in CWE, MITRE ATT&CK, or OWASP
- Static analysis tools, fuzzing, and penetration testing

You do **not** need prior Rust experience. We assume familiarity with systems programming concepts but start from the beginning with Rust itself. What we *don't* do is waste your time explaining what a pointer is. Instead, we focus on how Rust's ownership model replaces manual memory management, how its type system prevents common vulnerability patterns, and how to leverage Rust's guarantees in security-critical code.

## How This Book Is Organized

The book is structured in five parts:

1. **Foundations** (Chapters 1-4): Rust basics through a security lens, including why Rust matters, setup, ownership/borrowing, and the type system.
2. **Secure by Design** (Chapters 5-8): Error handling, concurrency safety, input validation, and cryptography, including core patterns for writing secure software.
3. **Systems Programming** (Chapters 9-12): Unsafe Rust, FFI, memory layout, and network programming, allowing to bridge the gap between safe abstractions and the bare metal.
4. **Assurance and Verification** (Chapters 13-16): Testing, fuzzing, static analysis, and supply chain security, in order to  prove your code is correct.
5. **Practical Secure Systems** (Chapters 17-19): Three hands-on projects that bring everything together, a hardened TCP server, a secure parser, and deployment hardening.

## A Note on Mindset

As a security-focused developer, you are accustomed to asking "what can go wrong?" Rust asks a different question: "what can the compiler prove is correct?" Learning to trust and verify the compiler is a key part of the Rust experience. But Rust also provides escape hatches (`unsafe`), and knowing when and how to use them safely is critical. This book spends significant time on that topic.

## Conventions

Throughout this book:

- Code examples use **Rust Edition 2024** unless noted otherwise. Edition 2024 stabilized in **Rust 1.85.0**, so install **Rust 1.85.0 or later** before working through the chapters. If `rustc --version` reports an older toolchain, run `rustup update stable` first. Nightly-only features are called out explicitly when they appear.
- Standalone Rust snippets are written to be `mdbook test` friendly whenever practical. Multi-file, async-runtime, or external-crate examples that stay marked `ignore` are illustrative excerpts; their tested counterparts live in the companion crates under `companion/`.
- CI verifies the companion code with `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `mdbook build`, and a fresh host-specific snippet-helper build before running `mdbook test -L .../debug/deps`.
- Security-relevant tips are marked with a 🔒 icon.
- Common pitfalls are marked with a ⚠️ icon.
- CWE references are provided where relevant, e.g., `CWE-119` for buffer overflows.

Let's begin.
