# Chapter 3 — Ownership, Borrowing, and Lifetimes

> *"You don't free memory in Rust. The compiler decides when to free it, and it never gets it wrong."*

This is the most important chapter in the book. Rust's ownership model is what makes the language unique, and understanding it deeply is essential for writing secure systems code. If you come from C/C++, you are used to manually managing memory with `malloc`/`free` or `new`/`delete`. Rust replaces this with a set of compile-time rules that guarantee memory safety without garbage collection.

## 3.1 Ownership Rules

Every value in Rust has exactly one **owner**—a variable that is responsible for its lifetime. When the owner goes out of scope, the value is dropped (memory is freed, destructors run). The three fundamental rules are:

1. Each value has exactly one owner.
2. When the owner goes out of scope, the value is dropped.
3. Values can be **moved** to a new owner or **borrowed** by references.

```rust
fn main() {
    let s1 = String::from("hello");  // s1 owns the String
    let s2 = s1;                     // ownership moves to s2
    // println!("{}", s1);           // ERROR: s1 no longer valid
    println!("{}", s2);              // OK: s2 is the owner
}   // s2 is dropped here, memory freed
```

This is a **move**—ownership transfers from `s1` to `s2`. The compiler prevents use-after-free by making `s1` inaccessible after the move.

🔒 **Security impact**: Eliminates CWE-416 (Use-After-Free) and double-free bugs. In C, transferring a string pointer without clear ownership conventions leads to double-free or use-after-free. Rust enforces this at compile time.

### 3.1.1 The `Copy` Trait

Some types are so small that copying them is cheaper than managing ownership. Types that implement the `Copy` trait are implicitly copied on assignment instead of moved:

```rust
fn main() {
    let x: i32 = 42;
    let y = x;        // x is copied (i32 implements Copy)
    println!("{}", x); // OK: x is still valid
    println!("{}", y); // OK: y has its own copy
}
```

Types that implement `Copy`: all integer types, `f32`/`f64`, `bool`, `char`, tuples of `Copy` types, and arrays of `Copy` types.

Types that do **not** implement `Copy`: `String`, `Vec<T>`, `Box<T>`, and any type that manages a resource (heap memory, file handles, etc.).

⚠️ **Security note**: Custom types should `#[derive(Copy, Clone)]` only when appropriate. Blindly deriving `Copy` for types containing handles or pointers can lead to logic errors.

### 3.1.2 Cloning When You Need Duplication

When you actually need a deep copy, use `.clone()`:

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = s1.clone();   // Deep copy, both are valid
    println!("{} {}", s1, s2);
}
```

## 3.2 Borrowing and References

Instead of transferring ownership, you can **borrow** a value via references. There are two kinds:

- **Immutable references** (`&T`): Allow reading but not modification. Multiple immutable borrows are allowed simultaneously.
- **Mutable references** (`&mut T`): Allow modification. Only **one** mutable borrow is allowed at a time, and it cannot coexist with any immutable borrows.

```rust
fn calculate_length(s: &String) -> usize {  // borrow immutably
    s.len()
}   // s goes out of scope but since it doesn't have ownership, nothing happens

fn append_world(s: &mut String) {           // borrow mutably
    s.push_str(", world");
}

fn main() {
    let mut greeting = String::from("hello");
    
    // Immutable borrow
    let len = calculate_length(&greeting);
    println!("'{}' has length {}", greeting, len);
    
    // Mutable borrow
    append_world(&mut greeting);
    println!("{}", greeting);  // "hello, world"
}
```

### 3.2.1 The Borrowing Rules Enforced

The compiler enforces these rules strictly:

```rust
fn main() {
    let mut data = vec![1, 2, 3, 4, 5];
    
    // Rule 1: Multiple immutable borrows OK
    let r1 = &data[0];
    let r2 = &data[1];
    println!("{} {}", r1, r2);  // OK
    
    // Rule 2: Mutable borrow must be exclusive
    let r3 = &mut data;
    // let r4 = &data[0];       // ERROR: cannot borrow immutably while mutably borrowed
    r3.push(6);
    println!("{:?}", r3);
    
    // Rule 3: Mutable borrows are exclusive
    // let r5 = &mut data;      // ERROR: cannot have two mutable borrows
}
```

🔒 **Security impact**: These rules eliminate:
- **CWE-416 (Use-After-Free)**: References cannot outlive the data they reference.
- **CWE-366 (Data Race)**: Two threads cannot have mutable access to the same data simultaneously without synchronization.
- **Iterator invalidation**: Modifying a collection while iterating is a compile error.

### 3.2.2 Preventing Iterator Invalidation

A classic C++ bug that leads to crashes and security vulnerabilities:

```cpp
// C++ - DANGEROUS: iterator invalidation
std::vector<int> v = {1, 2, 3};
for (auto it = v.begin(); it != v.end(); ++it) {
    if (*it == 2) {
        v.push_back(4);  // May reallocate, invalidating `it`
        // `it` is now dangling - use-after-free!
    }
}
```

Rust prevents this at compile time:

```rust
fn main() {
    let mut v = vec![1, 2, 3];
    for val in &v {           // immutable borrow of v
        // v.push(4);         // ERROR: cannot borrow mutably while borrowed immutably
        println!("{}", val);
    }
    v.push(4);                // OK: borrow ended
}
```

## 3.3 Lifetimes

Every reference in Rust has a **lifetime**—the scope for which the reference is valid. Most of the time, lifetimes are implicit and inferred. But when the compiler cannot determine the relationship between reference lifetimes, you must annotate them explicitly.

### 3.3.1 The Problem Lifetimes Solve

Consider this function:

```rust,compile_fail
// What does the compiler need to know?
fn longest(x: &str, y: &str) -> &str {
    if x.len() > y.len() { x } else { y }
}
```

The compiler cannot know whether the returned reference came from `x` or `y`. We must specify the relationship:

```rust
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}
```

The annotation `<'a>` says: "the returned reference lives as long as the *shorter* of `x` and `y`'s lifetimes."

```rust
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

fn main() {
    let s1 = String::from("long string");
    let result;
    {
        let s2 = String::from("short");
        result = longest(s1.as_str(), s2.as_str());
        println!("{}", result);  // OK: s2 still alive
    }
    // println!("{}", result);  // ERROR: s2 is dead, result may refer to it
}
```

🔒 **Security impact**: Lifetimes guarantee that no reference can outlive the data it points to. This is the compile-time equivalent of proving the absence of dangling pointers.

### 3.3.2 Lifetime Elision Rules

You don't always need to write lifetime annotations. The compiler applies three rules:

1. Each reference parameter gets its own lifetime.
2. If there's exactly one input lifetime, it's assigned to all output lifetimes.
3. If there are multiple input lifetimes but one is `&self` or `&mut self`, that lifetime is assigned to all outputs.

```text
// Elided (implicit)
fn first_word(s: &str) -> &str

// Expanded (explicit)
fn first_word<'a>(s: &'a str) -> &'a str
```

### 3.3.3 Struct Lifetimes

Structs that hold references must specify lifetimes:

```rust
struct Parser<'a> {
    input: &'a str,
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Parser { input, position: 0 }
    }
    
    fn peek(&self) -> Option<char> {
        self.input.chars().nth(self.position)
    }
}
```

This ensures the `Parser` cannot outlive the `input` string it references.

## 3.4 Common Patterns for Security Developers

### 3.4.1 The `Drop` Trait — Deterministic Cleanup

Rust's `Drop` trait is the equivalent of a C++ destructor. On normal return and unwinding paths, it runs deterministically when a value goes out of scope:

```rust
struct SecureBuffer {
    data: Vec<u8>,
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Zero the buffer before freeing memory using volatile writes
        // to prevent the compiler from optimizing away the zeroing.
        for byte in self.data.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        // Memory barrier to ensure the writes are not reordered
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        // Vec will be freed after this
    }
}

fn main() {
    let key = SecureBuffer {
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    // When `key` goes out of scope, the buffer is zeroed and freed
}
```

🔒 **Security pattern**: Use `Drop` to hook cleanup of sensitive data (cryptographic keys, passwords, tokens) on normal destruction paths. This is the Rust equivalent of calling `SecureZeroMemory` on Windows or `explicit_bzero` on POSIX before releasing the buffer.

⚠️ **Important**: A naive loop like `for byte in data.iter_mut() { *byte = 0; }` can be **optimized away** by LLVM because the `Vec` is about to be deallocated and the writes appear to have no observable effect. The `write_volatile` example above shows the low-level mechanics, but in practice you should prefer the `zeroize` crate:

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate zeroize;
use zeroize::Zeroize;

#[derive(zeroize::Zeroize)]
#[zeroize(drop)]  // Automatically zeroize on Drop
struct SecureBuffer {
    data: Vec<u8>,
}
```

Neither `Drop` nor `zeroize` is a complete secret-lifecycle guarantee. They do not run on paths such as `panic = "abort"`, `std::process::exit`, or deliberate leaks like `mem::forget`, and they do not erase copies of the secret that were already made elsewhere.

### 3.4.2 Interior Mutability — `RefCell<T>` and `Cell<T>`

Sometimes you need to mutate data even when there are immutable references to it. Rust provides safe interior mutability types:

```rust
use std::cell::RefCell;

struct Logger {
    messages: RefCell<Vec<String>>,
}

impl Logger {
    fn log(&self, msg: &str) {
        // Borrow mutably through the RefCell, even though self is immutable
        self.messages.borrow_mut().push(msg.to_string());
    }
    
    fn dump(&self) -> Vec<String> {
        self.messages.borrow().clone()
    }
}
```

⚠️ **Security note**: `RefCell` enforces borrowing rules at **runtime** instead of compile time. If you violate the rules (e.g., calling `borrow_mut()` while a `borrow()` is active), the program panics. Use `RefCell` only when you cannot satisfy the borrow checker at compile time, and ensure your usage patterns cannot lead to panics.

### 3.4.3 Self-Referential Types and `Pin`

Self-referential types (structs where one field references another) are a challenge in Rust. Most developers encounter this indirectly through `async fn`: the compiler-generated future may hold references into its own state machine, so it must not be moved after polling begins.

`Pin<P>` is the tool Rust uses to express that guarantee. Pinning does not magically make arbitrary self-references safe; it only promises that the pointee will not move after it has been pinned. If you think you need a hand-written self-referential struct, first try a simpler design: store offsets instead of references, split the owned buffer from the parsed view, or borrow from an external owner instead of borrowing from `self`.

🔒 **Security relevance**: `Pin` matters when implementing low-level async runtimes, protocol state machines, or custom pointer types. Used correctly, it prevents bugs where internal references are invalidated by moves. Used incorrectly with `unsafe`, it can recreate the same dangling-reference class Rust normally eliminates.

## 3.5 Ownership Compared to C/C++ Patterns

| Pattern | C/C++ | Rust |
|---------|-------|------|
| Single owner | Manual convention | Enforced by compiler |
| Shared ownership | Shared pointers (`shared_ptr`) | `Arc<T>` (atomic reference count) |
| Unique ownership | `unique_ptr` | `Box<T>` (or plain binding) |
| Borrowing | Raw pointers, no rules | References with compile-time rules |
| Lifetime management | Manual / RAII | Compiler-enforced RAII |
| Double-free | Possible | Impossible (ownership transfer) |
| Use-after-free | Possible | Impossible (borrow checker) |
| Dangling pointer | Possible | Impossible (lifetimes) |

## 3.6 Summary

- Every value has exactly one owner; when the owner is dropped, the value is freed.
- References borrow values without taking ownership, governed by strict rules.
- The borrow checker enforces: either one mutable reference **or** any number of immutable references.
- Lifetimes ensure references cannot outlive the data they reference.
- `Drop` provides deterministic cleanup on normal destruction paths; use it to hook secure wiping, but do not assume it runs on abort or forced-exit paths.
- Interior mutability (`RefCell`, `Cell`) moves borrow checking to runtime; use sparingly.

Understanding ownership is the foundation. In the next chapter, we explore Rust's type system and how it prevents entire categories of security bugs.

## 3.7 Exercises

1. **Borrow Checker Exploration**: Write a function that attempts to hold an immutable reference to a `Vec` while pushing a new element. Observe the compiler error. Then fix the code by restructuring it so the borrow ends before the mutation. Document which CWE class this prevents.

2. **Lifetime Annotations**: Write a function `first_two_words(s: &str) -> (&str, &str)` that returns the first two space-separated words. Add explicit lifetime annotations. Then write a `main` that demonstrates a case where the compiler correctly rejects use of the result after the original `String` is dropped.

3. **Custom Drop**: Implement a struct `SecureBuffer` that holds a `Vec<u8>` and implements both `wipe(&mut self)` and `Drop`. Write a test that calls `wipe()` and verifies the buffer is zeroed before deallocation, then have `Drop` call the same wipe logic. Do not read memory after drop; that would itself be undefined behavior.

4. **RefCell Safety**: Create a `RefCell<Vec<i32>>` and write code that attempts to call `.borrow()` while a `.borrow_mut()` is active. Observe the runtime panic. Compare this to what would happen in C++ with undefined behavior.
