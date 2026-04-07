# Chapter 10 - Foreign Function Interface

> *"The boundary between Rust and C is the most dangerous place in your codebase."*

Real-world systems need to interact with existing C libraries, operating system APIs, and legacy codebases. Rust's FFI (Foreign Function Interface) allows seamless interop with C, but every FFI boundary is a security checkpoint: data crosses from the safe, compiler-verified world of Rust into the unsafe, manually-managed world of C, and vice versa.

## 10.1 Calling C from Rust

### 10.1.1 Basic FFI Declarations

```rust,no_run
unsafe extern "C" {
    // Declare external C functions
    fn malloc(size: usize) -> *mut std::ffi::c_void;
    fn free(ptr: *mut std::ffi::c_void);
    fn strlen(s: *const std::ffi::c_char) -> usize;
}

fn c_string_length(s: &std::ffi::CStr) -> usize {
    unsafe {
        strlen(s.as_ptr())
    }
}
```

If you already have a Rust `&CStr`, prefer `s.to_bytes().len()` in real code. The `strlen` call here is purely to demonstrate declaring and calling a C function from Rust.

In Edition 2024, `extern` blocks are explicitly `unsafe` because Rust cannot verify that the foreign signatures are correct.

🔒 **Security rules for calling C**:
1. Assume the C function can corrupt memory.
2. Validate all inputs before passing to C.
3. Validate all outputs from C before using them.
4. Ensure C code cannot cause Rust's destructor-based cleanup to misbehave.
5. Be aware that C code may call `longjmp` or raise C++ exceptions, which is UB if it crosses into Rust frames.

### 10.1.2 The `bindgen` Tool

Manually writing FFI bindings is error-prone. Use `bindgen` to generate them from C headers:

```bash
cargo install bindgen-cli --version 0.71 --locked
bindgen /usr/include/openssl/ssl.h -o ssl_bindings.rs
```

Or use the `build.rs` pattern:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::bindgen as bindgen;
// build.rs
use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
```

```rust,no_run
// src/lib.rs
#[cfg(any())]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
```

### 10.1.3 String Interoperability

Converting between Rust strings and C strings is a common source of bugs:

```rust
use std::ffi::{CStr, CString, c_char};

/// SAFELY call a C function that takes a null-terminated string
fn call_c_with_string(input: &str) -> Result<i32, std::ffi::NulError> {
    // CString ensures null-termination and no embedded null bytes
    let c_string = CString::new(input)?;
    
    let result = unsafe {
        c_function_taking_string(c_string.as_ptr())
    };
    
    Ok(result)
}

/// Borrow from an existing `&CStr` when some other Rust value already proves
/// the lifetime.
fn borrow_c_string(raw: &CStr) -> Option<&str> {
    raw.to_str().ok()
}

/// # Safety
/// `raw` must point to a valid, NUL-terminated C string for the duration of
/// this call.
unsafe fn receive_c_string_owned(raw: *const c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    
    unsafe {
        CStr::from_ptr(raw).to_str().ok().map(|s| s.to_owned())
    }
}

unsafe extern "C" {
    fn c_function_taking_string(s: *const c_char) -> i32;
}
```

`receive_c_string_owned` stays `unsafe` even with a null check. Rust still cannot prove that a non-null pointer is valid, correctly terminated, properly aligned, or alive for the required lifetime.

Do not invent a lifetime from a raw pointer and return `&'a str` directly. If the C API gives you only `*const c_char`, copying into an owned `String` is the safest general default. Return a borrowed `&str` only when some other Rust value, such as an existing `&CStr`, already anchors the lifetime.

⚠️ **Security pitfalls**:
- **Embedded nulls**: `CString::new()` rejects strings with embedded `\0`. In C, a null byte terminates the string. If you need to pass binary data, use `*const u8` with an explicit length.
- **Lifetime**: C strings returned from C functions may be freed by the C library. Copy the data if you need it to outlive the C function's lifetime.
- **UTF-8 validation**: C strings are not necessarily valid UTF-8. Use `CStr::to_str()` which validates.

## 10.2 Calling Rust from C

### 10.2.1 Exporting Rust Functions

```rust
# #[derive(Debug)]
# enum ProcessingError {
#     Empty,
# }
# #[repr(C)]
# pub struct AddResult {
#     pub success: bool,
#     pub value: i32,
#     pub error_code: i32,
# }
#
#[unsafe(no_mangle)]
pub extern "C" fn rust_add_checked(a: i32, b: i32) -> AddResult {
    match a.checked_add(b) {
        Some(value) => AddResult {
            success: true,
            value,
            error_code: 0,
        },
        None => AddResult {
            success: false,
            value: 0,
            error_code: 1,
        },
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// `data` must either be null or point to `len` readable bytes for the
/// duration of this call.
pub unsafe extern "C" fn process_buffer(data: *const u8, len: usize) -> i32 {
    // Validate inputs
    if data.is_null() {
        return -1;
    }
    if len > MAX_BUFFER_SIZE {
        return -2;
    }
    
    // Wrap in catch_unwind to prevent panics from crossing FFI boundary
    let result = std::panic::catch_unwind(|| {
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        process_data(slice)
    });
    
    match result {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => -3,
        Err(_) => -4,  // Panic occurred
    }
}

const MAX_BUFFER_SIZE: usize = 1024 * 1024;  // 1 MiB limit

fn process_data(data: &[u8]) -> Result<i32, ProcessingError> {
    // Safe Rust processing
    if data.is_empty() {
        return Err(ProcessingError::Empty);
    }
    Ok(data.len() as i32)
}
```

In Edition 2024, `no_mangle` is an unsafe attribute, so exported symbols are written as `#[unsafe(no_mangle)]`.
Pointer validation does not make the function safe to call from Rust: the caller still owns the obligation to pass a live, correctly sized buffer.

Avoid sentinel return values for arithmetic helpers unless the ABI guarantees one value is impossible. Returning `0` on overflow, for example, silently conflates failure with a valid sum. A small `#[repr(C)]` status struct or explicit out-parameter keeps the contract unambiguous.

🔒 **Security checklist for Rust functions called from C**:
1. ✅ Mark raw-pointer entry points `unsafe extern "C" fn` so the safety contract is explicit on the Rust side.
2. ✅ Validate all pointer arguments (null check), while remembering that null checks do not prove provenance, alignment, or lifetime.
3. ✅ Validate all size/length arguments (bounds, max limits).
4. ✅ Wrap in `catch_unwind` to prevent panics from crossing FFI boundary.
5. ✅ Use `#[unsafe(no_mangle)]` (Edition 2024) and `extern "C"` for a stable ABI.
6. ✅ Never panic across the FFI boundary, it's undefined behavior.

When the foreign side is explicitly prepared to receive unwinding, stable Rust also offers `extern "C-unwind"`:

```rust
#[unsafe(no_mangle)]
pub extern "C-unwind" fn rust_callback_entry() {
    // Use this ABI only when the non-Rust caller documents unwind support.
}
```

Use `extern "C"` by default. `extern "C-unwind"` defines the ABI for interfaces that intentionally participate in unwinding; it is not a general excuse to let ordinary panics escape.

### 10.2.2 Exporting Rust Types

For complex interop, use `#[repr(C)]` to ensure C-compatible layout:

```rust,no_run
#[repr(C)]
pub struct FfiResult {
    pub success: u8,  // 1 = success, 0 = failure
    pub value: i64,
    pub error_code: i32,
    pub error_message: [u8; 256],
}

#[unsafe(no_mangle)]
pub extern "C" fn compute(x: i64, y: i64) -> FfiResult {
    match x.checked_mul(y) {
        Some(value) => FfiResult {
            success: 1,
            value,
            error_code: 0,
            error_message: [0; 256],
        },
        None => {
            let mut msg = [0u8; 256];
            let err = b"multiplication overflow";
            msg[..err.len()].copy_from_slice(err);
            FfiResult {
                success: 0,
                value: 0,
                error_code: 1,
                error_message: msg,
            }
        }
    }
}
```

## 10.3 The `cc` and `bindgen` Crates for Building C Code

### 10.3.1 Compiling C Code with `cc`

When you need to include C source code in your Rust project:

```toml
# [build-dependencies]
# cc = "1"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::cc as cc;
// build.rs
fn main() {
    cc::Build::new()
        .file("src/legacy_crypto.c")
        .flag("-O2")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror")          // Treat warnings as errors
        .flag("-fstack-protector-strong")  // Stack canaries
        .flag("-D_FORTIFY_SOURCE=2")       // Fortify source
        .compile("legacy_crypto");
}
```

🔒 **Security practice**: Apply the same hardening flags to C code that you would in a pure C project:
- `-fstack-protector-strong`: Stack canaries
- `-D_FORTIFY_SOURCE=2`: Buffer overflow detection in glibc functions
- `-fPIC`: Position-independent code (for shared libraries)
- `-Wl,-z,noexecstack`: Non-executable stack
- `-Wl,-z,relro`: Read-only relocations
- `-Wl,-z,now`: Full RELRO

### 10.3.2 Generating C Headers with `cbindgen`

When exposing Rust functions to C, you need C header files. `cbindgen` generates them automatically from your Rust code, ensuring the headers stay in sync:

```bash
cargo install cbindgen --version 0.29.2 --locked
cbindgen --config cbindgen.toml --crate my-lib --output my_lib.h
```

Or integrate into `build.rs`:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::cbindgen as cbindgen;
# use std::{env, path::PathBuf};
// build.rs
fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("my_lib.h");
    
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Unable to read cbindgen.toml");
    
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(out_path);
}
```

🔒 **Security practice**: Use `cbindgen` instead of writing headers manually. Manual headers can drift from the actual Rust function signatures, leading to type mismatches that cause undefined behavior at the FFI boundary. Write generated artifacts to `OUT_DIR` (or another explicit build output path), not a hardcoded `target/` path that breaks custom target directories and cross-compilation setups.

## 10.4 Dangerous C Patterns

### 10.4.1 `longjmp` and C++ Exceptions

⚠️ **Critical**: Never let `longjmp` (C) or C++ exceptions cross the Rust/C boundary. Doing so is undefined behavior: it bypasses Rust destructors, leaking resources and potentially corrupting the program state:

```rust,no_run
# struct ResourceGuard;
# fn acquire_resource() -> ResourceGuard {
#     ResourceGuard
# }
# unsafe fn c_library_do_jump() {}
// UNSOUND: if c_library_do_jump() calls longjmp, Rust destructors are bypassed
unsafe {
    let mut guard = acquire_resource();
    c_library_do_jump();  // If this longjmps, guard.drop() is never called!
}
```

If a C library uses `longjmp`, wrap it so the jump is caught on the C side before returning to Rust:

```c
// C wrapper
int safe_c_operation(void) {
    if (setjmp(buf) == 0) {
        return c_library_do_jump();  // Normal path
    } else {
        return -1;  // longjmp was caught, return error to Rust
    }
}
```

### 10.4.2 Using `-C panic=abort` for FFI Safety

When Rust code is called from C, a Rust panic that crosses the FFI boundary is undefined behavior. While `catch_unwind` can catch most panics, the safest approach is to compile with `-C panic=abort`:

```toml
# Cargo.toml
[profile.release]
panic = "abort"  # Panic immediately aborts the process instead of unwinding
```

With `panic = "abort"`:
- Panics terminate the process immediately: they cannot cross the FFI boundary.
- No unwinding tables: smaller binary, reduced attack surface.
- `catch_unwind` becomes a no-op (panics are no longer catchable).

⚠️ **Trade-off**: With `panic = "abort"`, you lose the ability to catch panics. Ensure all error handling uses `Result` rather than relying on panic catching.

See Chapter 5 for the panic-vs-`Result` design guidance that should shape the code before you rely on an aborting profile.

### 10.4.3 Signal Handlers and Thread-Local State

Signal handlers are a special FFI trap because they run in an async-signal-safe context, not in an ordinary Rust execution environment. Whether the handler is installed from C or from Rust, do **not** allocate, lock a mutex, log through a normal formatter, or touch most runtime/library facilities from the handler. Set an atomic flag, write a byte to a self-pipe or `eventfd`, and let ordinary code handle the real shutdown or recovery work.

Thread-local state deserves the same caution. A callback from C into Rust may run on a foreign thread that never initialized the Rust-side context you expected, and a signal can interrupt code while TLS-backed state is mid-update. Treat `thread_local!` values as thread-scoped implementation details, not as a cross-language global state mechanism.

## 10.5 Ownership Across the FFI Boundary

The most dangerous aspect of FFI is ownership confusion. Who allocates? Who frees?

### Pattern 1: Rust Allocates, Rust Frees

```rust
# const MAX_ALLOCATION: usize = 1024 * 1024;
#[unsafe(no_mangle)]
pub extern "C" fn create_buffer(size: usize) -> *mut u8 {
    if size == 0 || size > MAX_ALLOCATION {
        return std::ptr::null_mut();
    }
    let boxed = vec![0u8; size].into_boxed_slice();
    Box::into_raw(boxed) as *mut u8
}

#[unsafe(no_mangle)]
/// # Safety
/// `ptr` and `size` must come from `create_buffer`; `size` is the exact byte
/// length originally requested from `create_buffer`; and this function must be
/// called at most once for a given allocation.
pub unsafe extern "C" fn free_buffer(ptr: *mut u8, size: usize) {
    if !ptr.is_null() {
        unsafe {
            // Reconstruct the boxed slice using the original byte length.
            let slice = std::ptr::slice_from_raw_parts_mut(ptr, size);
            let _ = Box::from_raw(slice);
        }
    }
}
```

### Pattern 2: C Allocates, Rust Uses

```rust
pub struct CBuffer {
    ptr: *mut u8,
    len: usize,
}

impl CBuffer {
    /// # Safety
    /// `ptr` must be valid for reads of `len` bytes, allocated by C.
    pub unsafe fn from_c(ptr: *mut u8, len: usize) -> Option<Self> {
        if ptr.is_null() || len == 0 {
            return None;
        }
        Some(CBuffer { ptr, len })
    }
    
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

// Do NOT implement Drop to free the memory C owns it.
// If C expects Rust to free it, use the appropriate C deallocator.
```

🔒 **Golden rule**: Never mix allocators. If C allocates with `malloc`, free with `free`. If Rust allocates with `Box<[u8]>` or `Vec`, reconstruct the matching Rust type on the free path. Mixing allocators is undefined behavior.

## 10.6 Callbacks and Function Pointers

### C Calling Rust Callbacks

```rust,no_run
type Callback = extern "C" fn(i32, *const u8, usize) -> i32;

#[unsafe(no_mangle)]
pub extern "C" fn register_callback(cb: Option<Callback>) -> i32 {
    match cb {
        Some(callback) => {
            // Store the callback safely
            unsafe {
                GLOBAL_CALLBACK = Some(callback);
            }
            0
        }
        None => -1,
    }
}

static mut GLOBAL_CALLBACK: Option<Callback> = None;
```

⚠️ **Thread safety**: `static mut` is inherently unsafe for concurrent access. Use `Mutex` or atomic operations:

```rust
use std::sync::Mutex;

type Callback = extern "C" fn(i32, *const u8, usize) -> i32;

static GLOBAL_CALLBACK: Mutex<Option<Callback>> = Mutex::new(None);

fn register_callback_safe(cb: Option<Callback>) -> i32 {
    let mut guard = GLOBAL_CALLBACK.lock().expect("callback mutex poisoned");
    *guard = cb;
    0
}
```

## 10.7 Summary

- FFI is inherently unsafe: every boundary crossing requires careful validation.
- Use `bindgen` to generate bindings instead of writing them manually.
- Always validate inputs before passing to C and outputs from C.
- Use `catch_unwind` when Rust code is called from C to prevent panics from crossing the boundary.
- Use `#[repr(C)]` for stable ABI compatibility.
- Never mix allocators: match allocation and deallocation between Rust and C.
- Apply C hardening flags to any C code compiled in your project.
- Document ownership semantics clearly at every FFI boundary.

In the next chapter, we explore Rust's memory layout controls for systems programming.

## 10.8 Exercises

1. **Safe CString Wrapper**: Write a function `call_c_with_args(cmd: &str, args: &[&str]) -> Result<i32, FfiError>` that converts Rust strings to `CString`, calls a C function (simulate with a mock), and properly handles null bytes, NUL termination, and lifetime issues. Handle all error cases without `unwrap()`.

2. **Rust Library for C**: Create a Rust library that exports three functions via `#[unsafe(no_mangle)] extern "C"`: a string reverser, a buffer processor (with input validation), and a stateful counter. Write a C header file for it. Wrap every function in `catch_unwind`. Write tests in C that call these functions with various inputs including NULL pointers, zero-length buffers, and extremely large sizes.

3. **Ownership Across FFI**: Implement two FFI patterns: (a) Rust allocates a buffer, passes it to C, C fills it, Rust frees it; (b) C allocates, Rust processes, C frees. Use `#[repr(C)]` structs to pass metadata. Write tests verifying no memory leaks using a custom allocator.
