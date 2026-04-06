# Chapter 9 — Unsafe Rust: When and How

> *"With great power comes great responsibility—and a lot of code review."*

Unsafe Rust is the escape hatch that allows you to bypass the compiler's safety checks. It exists because there are things the compiler cannot verify: interfacing with C libraries, implementing low-level data structures, hardware access, and performance-critical optimizations that require raw pointer manipulation.

For security developers, `unsafe` is the most critical area of Rust code. Every unsafe block is a potential source of memory corruption, and must be audited with the same rigor you'd apply to C code.

## 9.1 What `unsafe` Enables

Inside an `unsafe` block, you can:

1. **Dereference raw pointers** (`*const T`, `*mut T`)
2. **Call unsafe functions** (including FFI functions)
3. **Access or modify mutable statics**
4. **Implement unsafe traits**
5. **Access fields of `union`s**

⚠️ **What `unsafe` does NOT disable**: The borrow checker still operates. `unsafe` does not turn off the type system, lifetimes, or other compile-time checks. It only allows the five operations listed above.

## 9.2 The Safety Invariant

Every `unsafe` block comes with an implicit contract: **you must ensure that safe code cannot cause undefined behavior through your unsafe code.**

This is the "soundness" property: safe Rust code can never cause undefined behavior, even if it tries. If safe code *can* cause UB through your unsafe abstraction, your code is **unsound**—and that's a bug.

```rust
// UNSOUND: safe code can cause UB
pub struct BadSlice<T> {
    ptr: *mut T,
    len: usize,
}

impl<T> BadSlice<T> {
    pub fn get(&self, index: usize) -> &T {
        unsafe {
            // BUG: no bounds check!
            &*self.ptr.add(index)
        }
    }
}

// A safe caller can trigger out-of-bounds read:
fn exploit() {
    let mut data = [1, 2, 3];
    let slice = BadSlice { ptr: data.as_mut_ptr(), len: 3 };
    let _val = slice.get(100);  // Out-of-bounds! UB through safe code!
}
```

The fix: add bounds checking:

```rust
# pub struct BadSlice<T> {
#     ptr: *mut T,
#     len: usize,
# }
#
impl<T> BadSlice<T> {
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        unsafe {
            Some(&*self.ptr.add(index))
        }
    }
}
```

🔒 **Golden rule of unsafe**: Safe code wrapping your unsafe abstraction must never be able to cause undefined behavior.

## 9.3 Unsafe Best Practices

### 9.3.1 Minimize the Scope of `unsafe`

```rust
# static VALUE: u32 = 42;
# fn get_pointer() -> *const u32 { &VALUE }
# fn process_value(_value: u32) {}
# fn store_result(_value: u32) {}
# fn log_action(_action: &str) {}
#
// BAD: large unsafe block
unsafe {
    let ptr = get_pointer();
    let value = *ptr;
    process_value(value);
    store_result(value);
    log_action("processed");
}

// GOOD: isolate the unsafe operation
let value = unsafe { *get_pointer() };  // Only the deref is unsafe
process_value(value);
store_result(value);
log_action("processed");
```

### 9.3.2 Document Safety Invariants

Every unsafe function and unsafe block must have a `# Safety` comment:

```rust
/// Reads a u32 from the given byte slice at the specified offset.
///
/// # Safety
///
/// The caller must ensure:
/// - `data` is valid for reads of 4 bytes starting at `offset`
/// - `offset + 4 <= data.len()`
pub unsafe fn read_u32_at(data: &[u8], offset: usize) -> u32 {
    let ptr = data.as_ptr().add(offset) as *const u32;
    std::ptr::read_unaligned(ptr)
}
```

🔒 **Security practice**: During code review, require that every `unsafe` block has a `# Safety` comment explaining why the operation is safe. If the comment is missing or incomplete, the code should not be merged.

### 9.3.3 Prefer Safe Abstractions

Wrap unsafe code in safe APIs:

```rust
use std::ptr::NonNull;

#[derive(Debug)]
pub enum RawVecError {
    CapacityOverflow,
    LayoutOverflow,
}

/// A vec-like structure that tracks allocated but uninitialized memory.
pub struct RawVec<T> {
    ptr: NonNull<T>,
    cap: usize,
}

impl<T> RawVec<T> {
    pub fn new() -> Self {
        let cap = if std::mem::size_of::<T>() == 0 { usize::MAX } else { 0 };
        RawVec {
            ptr: NonNull::dangling(),
            cap,
        }
    }
    
    pub fn with_capacity(capacity: usize) -> Result<Self, RawVecError> {
        let mut rv = Self::new();
        if capacity > 0 && std::mem::size_of::<T>() != 0 {
            rv.grow(capacity)?;
        }
        Ok(rv)
    }
    
    fn grow(&mut self, min_cap: usize) -> Result<(), RawVecError> {
        assert!(std::mem::size_of::<T>() != 0, "zero-sized types never allocate");
        let doubled = self.cap.checked_mul(2)
            .ok_or(RawVecError::CapacityOverflow)?;
        let new_cap = min_cap.max(doubled);
        let new_layout = std::alloc::Layout::array::<T>(new_cap)
            .map_err(|_| RawVecError::LayoutOverflow)?;
        
        let new_ptr = if self.cap == 0 {
            unsafe { std::alloc::alloc(new_layout) }
        } else {
            let old_layout = std::alloc::Layout::array::<T>(self.cap)
                .map_err(|_| RawVecError::LayoutOverflow)?;
            unsafe { std::alloc::realloc(self.ptr.as_ptr() as *mut u8, old_layout, new_layout.size()) }
        };
        
        self.ptr = match NonNull::new(new_ptr as *mut T) {
            Some(ptr) => ptr,
            None => std::alloc::handle_alloc_error(new_layout),
        };
        self.cap = new_cap;
        Ok(())
    }
    
    /// Returns a pointer to the buffer.
    /// 
    /// # Safety
    /// The caller must not write beyond `self.cap` elements.
    pub fn ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }
    
    pub fn capacity(&self) -> usize {
        self.cap
    }
}

impl<T> Drop for RawVec<T> {
    fn drop(&mut self) {
        if self.cap > 0 && std::mem::size_of::<T>() > 0 {
            let layout = std::alloc::Layout::array::<T>(self.cap)
                .expect("layout overflow in drop");
            unsafe {
                std::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
            }
        }
    }
}
```

This version turns size arithmetic failures into normal errors. It still mirrors the standard library's usual OOM behavior by delegating null allocations to `handle_alloc_error`; if you need attacker-controlled growth to fail recoverably instead of aborting, prefer fallible reserve patterns such as Chapter 18's `try_reserve_exact` example.

### 9.3.4 `UnsafeCell<T>` Is the Foundation of Interior Mutability

If shared state can be mutated through a shared reference, the storage must live inside `UnsafeCell<T>` (or a safe abstraction built on top of it, such as `Cell`, `RefCell`, `Mutex`, or atomics):

```rust
use std::cell::UnsafeCell;

pub struct SecretBox {
    bytes: UnsafeCell<[u8; 32]>,
}

impl SecretBox {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes: UnsafeCell::new(bytes),
        }
    }

    pub fn with_bytes<R>(&self, f: impl FnOnce(*mut [u8; 32]) -> R) -> R {
        f(self.bytes.get())
    }
}
```

`UnsafeCell` only opts out of Rust's usual "shared references are immutable" rule. It does **not** provide synchronization by itself. If the value is shared across threads, you still need a sound synchronization strategy.

### 9.3.5 Pointer Provenance Still Matters

Raw pointers are not just integer addresses; they are expected to be derived from the live allocation they access. In practice, that means:

- Derive pointers from real references or existing raw pointers (`as_ptr`, `as_mut_ptr`, `addr_of!`, `NonNull`).
- Keep pointer arithmetic within the original allocation.
- Do not reconstruct pointers from guessed integers and assume they are valid to dereference.

The exact formal model continues to evolve, but the review rule is stable: if a pointer did not come from the allocation it is used on, treat the code as suspect.

## 9.4 Common Unsafe Patterns and Pitfalls

### 9.4.1 Raw Pointer Dereferencing

```rust
fn deref_example() {
    let mut value = 42u32;
    let ptr: *mut u32 = &mut value;
    
    unsafe {
        // Direct dereference
        *ptr = 100;
        println!("{}", *ptr);
        
        // Offset arithmetic
        let arr = [1u32, 2, 3, 4];
        let arr_ptr = arr.as_ptr();
        let second = *arr_ptr.add(1);  // arr[1]
    }
}
```

⚠️ **Pitfall**: Pointer arithmetic can go out of bounds. Rust does not check pointer arithmetic at runtime. You must validate bounds yourself.

### 9.4.2 Transmute — Type Punning

`std::mem::transmute` reinterprets bytes as a different type. It is extremely dangerous:

```rust
// DANGEROUS: transmute can violate invariants
unsafe {
    let bytes: [u8; 4] = [0x41, 0x42, 0x43, 0x44];
    let value: u32 = std::mem::transmute(bytes);  // Endianness-dependent!
    
    // NEVER transmute references between types of different sizes
    // NEVER transmute &T to &mut T
}
```

🔒 **Security rule**: Avoid `transmute` for type punning and unrelated layout conversions. Prefer dedicated APIs such as `from_ne_bytes`, `to_be_bytes`, `MaybeUninit`, or crates like `zerocopy`/`bytemuck` where appropriate.

### 9.4.3 Uninitialized Memory

```rust
use std::mem::MaybeUninit;

fn initialize_array() -> [u32; 100] {
    let mut arr = MaybeUninit::<[u32; 100]>::uninit();
    let ptr = arr.as_mut_ptr() as *mut u32;

    for i in 0..100 {
        unsafe { ptr.add(i).write(42) };
    }

    // SAFETY: Every element was initialized exactly once above.
    unsafe { arr.assume_init() }
}
```

⚠️ **Never use `std::mem::zeroed()` for types where all-zeros is not a valid representation** (e.g., references, `NonNull`). Use `MaybeUninit` instead.

### 9.4.4 Shared Mutable State

A common unsound pattern: deriving `&mut T` from `&T`:

```rust,compile_fail
// UNSOUND: violates the aliasing rules
fn evil<T>(reference: &T) -> &mut T {
    unsafe {
        &mut *(reference as *const T as *mut T)
    }
}
```

This is undefined behavior because it violates Rust's aliasing model: you promised the compiler that `reference` is immutable, but then you mutate through it. The compiler may have optimized based on the immutability promise.

### 9.4.5 `unsafe impl Send/Sync`

The `Send` and `Sync` traits are automatically derived by the compiler, but sometimes you need to implement them manually for types containing raw pointers or non-thread-safe data. This is `unsafe` because incorrect implementations can cause data races:

```rust
use std::sync::atomic::{AtomicPtr, Ordering};

struct SharedRawBuf<T> {
    ptr: AtomicPtr<T>,
    cap: usize,
}

// SAFETY: SharedRawBuf uses AtomicPtr for thread-safe pointer access.
// All mutations go through atomic operations, so the type can be safely
// shared between threads (Sync) and moved between threads (Send).
unsafe impl<T: Send> Send for SharedRawBuf<T> {}
unsafe impl<T: Send> Sync for SharedRawBuf<T> {}
```

⚠️ **Pitfall**: Implementing `Send` for a type that is not thread-safe (e.g., contains `Rc<T>` or `Cell<T>`) will cause data races. Always verify that all internal state is properly synchronized before implementing these traits.

🔒 **Security practice**: Only implement `Send`/`Sync` when the type's internal synchronization guarantees thread safety. If unsure, do not implement them — the compiler's auto-derivation is conservative and correct by default.

### 9.4.6 Forbidding `unsafe` in Safe Code

For security-critical projects, you can use lints to control where `unsafe` is allowed:

```rust
// In lib.rs or main.rs — disallow unsafe code entirely
#![forbid(unsafe_code)]
```

```rust
// Allow unsafe only in specific modules
#![deny(unsafe_code)]

mod safe_module {
    // No unsafe allowed here
}

#[allow(unsafe_code)]
mod raw_bindings {
    // Unsafe allowed only in this module
    pub unsafe fn raw_read(ptr: *const u8) -> u8 {
        *ptr
    }
}
```

In Edition 2024, `unsafe_op_in_unsafe_fn` warns by default. On older editions, enable it explicitly to require `unsafe` blocks even inside `unsafe fn`:

```rust
// In lib.rs on Edition 2021 or earlier
#![warn(unsafe_op_in_unsafe_fn)]

unsafe fn process_raw(ptr: *const u8) -> u8 {
    // Without the lint, this would compile without an extra `unsafe` block.
    // With the lint, you must write:
    unsafe { *ptr }
}
```

🔒 **Security practice**: Use `#![forbid(unsafe_code)]` at the crate level for libraries that should have zero unsafe code. Use `#![deny(unsafe_code)]` with `#[allow(unsafe_code)]` on specific modules to concentrate unsafe code in auditable locations. Enable `unsafe_op_in_unsafe_fn` to ensure every individual unsafe operation is explicitly marked.

## 9.5 Auditing Unsafe Code

### 9.5.1 The Unsafe Audit Checklist

When reviewing `unsafe` code, verify:

- [ ] **Validity**: Are all pointers valid for the intended read/write?
- [ ] **Bounds**: Is all pointer arithmetic within allocated bounds?
- [ ] **Alignment**: Are pointer casts properly aligned?
- [ ] **Alias**: Are mutable references unique? No concurrent `&mut`?
- [ ] **Interior mutability**: Is shared mutation routed through `UnsafeCell` or a sound primitive built on it?
- [ ] **Initialization**: Is all read memory initialized?
- [ ] **Provenance**: Are raw pointers derived from the live allocation they access?
- [ ] **Thread safety**: Is shared state properly synchronized?
- [ ] **Lifetime**: Do references not outlive the data they point to?
- [ ] **Soundness**: Can safe code cause UB through this abstraction?
- [ ] **Documentation**: Is there a `# Safety` comment?

### 9.5.2 Tools for Unsafe Code

| Tool | Purpose |
|------|---------|
| `cargo miri` | Detects undefined behavior by interpreting your MIR |
| `loom` (`loom::model` in tests) | Model checker for concurrent code (detects data races, atomic violations) |
| Prusti | Formal verification of Rust programs using Viper |
| `cargo geiger` | Counts unsafe lines in your dependencies |
| `cargo crev` | Community code review for crates |
| `cargo vet` | Structured supply-chain auditing |

#### Using Miri

Miri is the most important tool for auditing `unsafe` code. It runs your program in a virtual machine that is instrumented to detect undefined behavior at runtime:

```bash
# Install nightly and miri
rustup toolchain install nightly
rustup component add miri --toolchain nightly
cargo +nightly miri test
```

Miri detects:
- Use of uninitialized memory
- Out-of-bounds pointer arithmetic
- Violation of the aliasing model (Stacked Borrows)
- Invalid values (e.g., `None` in a `NonZero` type)
- Use after free
- Data races (enabled by default)

```rust
fn main() {
    let mut data = vec![1, 2, 3];
    let ptr = data.as_mut_ptr();
    
    // Miri will catch this:
    unsafe {
        let _oob = *ptr.add(100);  // Out of bounds!
    }
}
```

🔒 **Security practice**: Run `cargo miri test` in CI for any crate that contains `unsafe` code. Miri does not prove the *absence* of bugs, but it is exceptionally effective at finding them.

For stricter pointer-provenance diagnostics, add `-Zmiri-strict-provenance`. If you want to experiment with Miri's alternative aliasing model, add `-Zmiri-tree-borrows`. These checks are separate from the data-race detector.

⚠️ **Limitations**: Miri supports many `std::thread` patterns, but it cannot execute arbitrary FFI, real network I/O, or many OS-specific interactions. For such code, extract the pure logic into testable functions and run Miri on those pieces.

#### Using Loom for Concurrency Testing

`loom` is a model checker that systematically explores all possible thread interleavings to find data races and concurrency bugs. It replaces `std::sync` primitives with mock versions that explore different execution orderings:

```toml
# [dev-dependencies]
# loom = "0.7"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::loom as loom;
// tests/concurrency.rs
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread;

#[test]
fn test_atomic_counter() {
    loom::model(|| {
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::clone(&counter);
        let c2 = Arc::clone(&counter);
        
        let t1 = thread::spawn(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        });
        
        let t2 = thread::spawn(move || {
            c2.fetch_add(1, Ordering::SeqCst);
        });
        
        t1.join().unwrap();
        t2.join().unwrap();
        
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    });
}
```

🔒 **Security practice**: Use `loom` to test any `unsafe` data structure that is accessed from multiple threads (e.g., custom lock implementations, lock-free queues, concurrent hash maps). It explores interleavings that are nearly impossible to trigger in regular testing.

#### Using Prusti for Formal Verification

Prusti is a verification tool that uses the [Viper](https://viper.ethz.ch/) infrastructure to formally prove properties about Rust code. It uses *specification annotations* to state what should be true:

```rust
// Prusti uses the `prusti-contracts` crate for specifications
// Currently requires a custom toolchain; see https://github.com/viperproject/prusti-dev

// Example (conceptual — requires Prusti toolchain):
// #[requires(x >= 0)]
// #[ensures(result >= 0)]
// fn safe_sqrt(x: i32) -> i32 {
//     // Prusti verifies at compile time that the postcondition holds
//     ...
// }
```

Prusti is still research-grade and best suited to small, focused proofs rather than "turn it on for the whole crate" CI. For security-critical components, it can provide mathematical guarantees that go beyond what testing can achieve, but treat it as a high-assurance specialist tool, not a drop-in replacement for normal review and testing.

## 9.6 Summary

- `unsafe` allows five specific operations that bypass safety checks.
- The soundness contract: safe code must never cause UB through your unsafe abstraction.
- Minimize `unsafe` scope, document safety invariants, wrap in safe APIs.
- `UnsafeCell` is the only legal foundation for interior mutability; it does not replace synchronization.
- Raw-pointer provenance matters: derive pointers from real allocations, not guessed addresses.
- Use `MaybeUninit` instead of `zeroed()` for uninitialized memory.
- Avoid `transmute`; use safe alternatives.
- **Use Miri** to detect UB in unsafe code, **Loom** to test concurrent data structures, and **Prusti** for formal verification when mathematical guarantees are required.
- Audit all unsafe code with the checklist.
- Use Miri to detect undefined behavior in tests.

In the next chapter, we explore the Foreign Function Interface—calling C code from Rust and vice versa, which is inherently unsafe and requires careful security consideration.

## 9.7 Exercises

1. **Soundness Audit**: Review the following unsound code. Identify both bugs, explain which safety invariant is violated, and fix it:
   ```rust,no_run
   pub struct FastMap<V> {
       entries: Vec<Option<(String, V)>>,
       size: usize,
   }
   impl<V> FastMap<V> {
       pub fn insert(&mut self, key: String, value: V) {
           let hash = key.len() % self.entries.len();
           unsafe { *self.entries.get_unchecked_mut(hash) = Some((key, value)); }
           self.size += 1;
       }
   }
   ```
   Consider both the empty-table case (`self.entries.len() == 0`, so the modulo panics) and the unchecked write path.

2. **Safe Wrapper**: Write a safe wrapper around a raw pointer-based circular buffer. The unsafe internals should use `MaybeUninit<T>` for the backing array. The public API must be fully safe: `push()`, `pop()`, and `get()` should never cause UB regardless of how they are called. Add a `# Safety` comment to every `unsafe` block, using the checklist in §9.5.1 to explain validity, bounds, aliasing/lifetimes, initialization, synchronization assumptions, and why safe callers cannot trigger UB.

3. **Miri Exploration**: Write a small function that creates undefined behavior (e.g., use-after-free via raw pointer, or out-of-bounds access via `get_unchecked`). Run it under normal execution (it may appear to work), then run it under `cargo miri` and observe the detection. Fix the bug and verify Miri passes.
