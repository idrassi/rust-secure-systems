# Chapter 11 — Memory Layout and Low-Level Control

> *"Know your memory. Know your adversary."*

Systems programming requires precise control over memory layout: network protocols define wire formats, hardware registers have fixed offsets, and kernel structures must match ABI conventions. Rust provides tools for controlling memory layout while maintaining safety at the boundaries.

## 11.1 Representations: `repr`, Alignment, and Padding

### 11.1.1 Default Rust Layout

By default, Rust's compiler is free to reorder struct fields and add padding for alignment:

```rust
struct NetworkHeader {
    version: u8,     // 1 byte
    flags: u8,       // 1 byte
    length: u16,     // 2 bytes (might be padded)
    seq: u32,        // 4 bytes
    ack: u32,        // 4 bytes
}
// Size: might be 12, 14, or 16 bytes depending on compiler decisions
```

This is fine for internal use but **dangerous** for parsing external data.

### 11.1.2 `#[repr(C)]` — C-Compatible Layout

```rust
#[repr(C)]
struct CNetworkHeader {
    version: u8,    // offset 0
    flags: u8,      // offset 1
    length: u16,    // offset 2
    seq: u32,       // offset 4
    ack: u32,       // offset 8
}
// Size: exactly 12 bytes on common ABIs, with no interior padding in this layout
```

`#[repr(C)]` guarantees:
- Fields are laid out in declaration order.
- Padding follows C ABI rules for the target platform.
- The struct can be safely passed across FFI boundaries.

🔒 **Security pattern**: Always use `#[repr(C)]` for structs that:
- Map to hardware registers
- Define network wire formats
- Are shared with C code
- Are cast from raw byte arrays

### 11.1.3 `#[repr(C, packed)]` — No Padding

```rust
#[repr(C, packed)]
struct PackedHeader {
    version: u8,
    length: u16,  // No padding, but may be misaligned!
    seq: u32,
}
```

⚠️ **Danger**: Packed structs can cause unaligned memory access, which is:
- Undefined behavior on some architectures (ARM, SPARC)
- Slower on x86
- Potentially a security issue (different behavior on different platforms)

🔒 **Rule**: Only use `#[repr(packed)]` for network packet parsing where the wire format has no padding. Always use `read_unaligned` and `write_unaligned`:

```rust
use std::{mem::size_of, ptr};

# #[repr(C, packed)]
# struct PackedHeader {
#     version: u8,
#     length: u16,
#     seq: u32,
# }
#
fn read_packed_header(data: &[u8]) -> Option<PackedHeader> {
    if data.len() < size_of::<PackedHeader>() {
        return None;
    }
    let ptr = data.as_ptr() as *const PackedHeader;
    Some(unsafe { ptr::read_unaligned(ptr) })
}
```

### 11.1.4 `#[repr(u8)]`, `#[repr(i32)]` — Enum Size Control

```rust
#[repr(u8)]
enum PacketType {
    Syn = 0x01,
    Ack = 0x02,
    Data = 0x03,
    Fin = 0x04,
}
// Guaranteed: sizeof(PacketType) == 1
```

### 11.1.5 `#[repr(transparent)]` — Single-Field Wrapper

```rust
#[repr(transparent)]
struct WrappedU64(u64);

// WrappedU64 has the exact same layout as u64
// Useful for newtypes that need FFI compatibility
```

## 11.2 Safe Parsing of Binary Data

### 11.2.1 The `zerocopy` Crate

Parsing binary data without copying is both a performance and security concern. Once you have a `#[repr(C)]` header type that derives the required `zerocopy` traits, parsing is straightforward:

```toml
[dependencies]
zerocopy = "0.8"
```

```rust,no_run
# extern crate rust_secure_systems_book;
use rust_secure_systems_book::deps::zerocopy::TryFromBytes;
# use rust_secure_systems_book::zerocopy_examples::TcpHeader;

fn parse_tcp_header(data: &[u8]) -> Option<&TcpHeader> {
    TcpHeader::try_ref_from_bytes(data).ok()
}
```

🔒 **Security advantage**: `zerocopy` verifies that:
- The data is large enough for the type
- Alignment requirements are met
- No uninitialized memory is read

### 11.2.2 Manual Byte Parsing with `from_be_bytes`

For simpler cases, use the standard library's byte conversion:

```rust
fn parse_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes: [u8; 2] = data.get(offset..end)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn parse_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(offset..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}
```

🔒 **Security practice**: Always use explicit endianness (`from_be_bytes`, `from_le_bytes`) rather than platform-dependent casts. Network protocols are big-endian; x86 is little-endian. Mixing them up is a subtle and dangerous bug.

## 11.3 Alignment and the `align` Representation

### 11.3.1 Controlling Alignment

```rust
#[repr(C)]
#[repr(align(16))]  // 16-byte aligned (useful for SIMD, DMA buffers)
struct AlignedBuffer {
    data: [u8; 4096],
}
```

🔒 **Security relevance**: Some low-level interfaces benefit from aligned buffers:
- SIMD and DMA interfaces may require or strongly prefer specific alignment
- Alignment can reduce performance variance and avoid unaligned-access traps on some targets
- Do not assume a crypto primitive requires a specific alignment unless its API or hardware manual says so

### 11.3.2 Cache-Line Alignment

```rust
#[repr(C)]
#[repr(align(64))]  // Common cache-line size on modern x86-64/ARM64; verify on your target
struct CacheLineAligned {
    // Align the counter to reduce false sharing between adjacent instances.
    counter: std::sync::atomic::AtomicU64,
}
```

🔒 **Security relevance**: Reduces false sharing between threads, which can otherwise increase timing noise and contention. Treat this as a performance and isolation aid, not as a standalone side-channel defense.

## 11.4 Working with Raw Memory

### 11.4.1 The Global Allocator

Rust uses the system allocator by default. For security-sensitive applications, you can use a custom allocator:

```rust,no_run
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{compiler_fence, Ordering};

/// A simple allocator that zeroizes memory on free
struct SecureAllocator;

unsafe impl GlobalAlloc for SecureAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !ptr.is_null() {
            for i in 0..layout.size() {
                unsafe { ptr.add(i).write_volatile(0); }
            }
            compiler_fence(Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static GLOBAL: SecureAllocator = SecureAllocator;
```

⚠️ **Note**: This is a simplified example. A production secure allocator should also:
- Lock pages containing keys (prevent swapping to disk)
- Use `mlock`/`VirtualLock` to prevent paging
- Use a zeroization primitive that is guaranteed not to be optimized away
- Guard against heap metadata corruption

### 11.4.2 The `zeroize` Crate — Practical Memory Wiping

The `zeroize` crate gives you a practical way to wipe specific buffers before release, unlike naive manual loops that the compiler may optimize away:

```toml
[dependencies]
zeroize = { version = "1", features = ["derive"] }
```

```rust,no_run
# extern crate rust_secure_systems_book;
# extern crate zeroize;
use zeroize::Zeroize;

struct CryptoKey {
    material: [u8; 32],
}

impl Drop for CryptoKey {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

// Or use the derive macro for automatic zeroization:
#[derive(zeroize::Zeroize)]
#[zeroize(drop)]
struct SessionKey {
    key: [u8; 32],
    iv: [u8; 12],
}
// On normal drop paths, both `key` and `iv` are zeroized before release.

// Also works with Vec and other heap-allocated types:
#[derive(zeroize::Zeroize)]
#[zeroize(drop)]
struct SecureBuffer {
    data: Vec<u8>,
}
```

🔒 **Security practice**: Use `zeroize` (with the `derive` feature) instead of manual zeroing loops. The crate is designed so the wipe operation itself is not optimized away, but it only affects the buffer you zeroize and only on code paths where zeroization runs. It does not erase copies you already made, and it cannot help if the process aborts or exits before `Drop`.

### 11.4.3 Safe Pointer Access with `addr_of!` and `addr_of_mut!`

When working with structs that contain fields you cannot safely create (e.g., a `MaybeUninit` field), use `addr_of!` and `addr_of_mut!` to obtain pointers without creating intermediate references:

```rust
use std::mem::MaybeUninit;
use std::ptr::{addr_of, addr_of_mut};

#[repr(C)]
struct PacketBuffer {
    header: [u8; 4],
    payload: MaybeUninit<[u8; 1024]>,
}

impl PacketBuffer {
    fn new() -> Self {
        PacketBuffer {
            header: [0; 4],
            payload: MaybeUninit::uninit(),
        }
    }
    
    fn write_payload(&mut self, data: &[u8]) {
        let payload_ptr = addr_of_mut!(self.payload);
        unsafe {
            let raw = (*payload_ptr).as_mut_ptr() as *mut u8;
            raw.copy_from_nonoverlapping(data.as_ptr(), data.len().min(1024));
        }
    }
    
    fn read_header(&self) -> &[u8; 4] {
        // addr_of! creates a pointer without creating a reference,
        // which is safe even if the struct has uninitialized fields
        let header_ptr = addr_of!(self.header);
        unsafe { &*header_ptr }
    }
}
```

🔒 **Security practice**: Prefer `addr_of!`/`addr_of_mut!` over `&self.field` or `&mut self.field` when the struct may contain uninitialized data. Creating a reference to uninitialized memory is instant UB, even if you never read through it.

### 11.4.4 Memory Locking (Prevent Swapping)

```rust,no_run
# extern crate rust_secure_systems_book;
# #[cfg(unix)]
# use rust_secure_systems_book::deps::libc as libc;
# use rust_secure_systems_book::deps::windows_sys as windows_sys;
#[cfg(unix)]
fn lock_memory(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn lock_memory(ptr: *const u8, len: usize) -> Result<(), std::io::Error> {
    use windows_sys::Win32::System::Memory::VirtualLock;
    let result = unsafe { VirtualLock(ptr.cast(), len) };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
```

🔒 **Security impact**: Prevents sensitive data (keys, passwords) from being written to the swap file, where they could persist after the process exits (CWE-316: Cleartext Storage of Sensitive Information).

## 11.5 Stack and Heap Security

### 11.5.1 Stack Protection

Rust already enables stack probing/stack-clash protection on mainstream targets, but stable Rust does **not** enable stack canaries for Rust code by default. Keep frame pointers for profiling and post-mortem analysis, and treat C/C++ stack canaries as a separate hardening step for any non-Rust objects you compile:

```toml
# .cargo/config.toml
[build]
rustflags = ["-C", "force-frame-pointers=yes"]
```

If you build C/C++ code via the `cc` crate, apply `-fstack-protector-strong` to those objects separately. For RELRO, NX, and PIE settings, use the linker hardening flags from Chapter 19. Frame pointers improve observability; they are not a canary mechanism.

### 11.5.2 Guard Pages

Rust's default allocator does **not** place guard pages between heap allocations — neither in debug nor release mode. Guard pages exist at stack boundaries (enforced by the OS), not between individual heap allocations. For heap-level guard page protection, use a hardened allocator like GWP-ASan or run under AddressSanitizer (ASan):

```bash
# Run with ASan to detect heap buffer overflows
RUSTFLAGS="-Zsanitizer=address" cargo +nightly run
```

```toml
[dependencies]
tikv-jemallocator = "0.6"
```

```rust,no_run
// Replace `System` with a custom allocator crate if your deployment needs
// allocator-specific hardening features.
#[global_allocator]
static GLOBAL: std::alloc::System = std::alloc::System;
```

## 11.6 WebAssembly (Wasm) for Security Sandboxing

WebAssembly provides a lightweight sandboxing mechanism that is increasingly used to isolate untrusted code. Rust has first-class Wasm support, making it a natural choice for building secure plugin systems, policy engines, and sandboxed extensions.

### 11.6.1 Why Wasm for Security?

Wasm offers a **principled sandbox** with strong guarantees:
- **Linear memory isolation**: A Wasm module can only access its own linear memory—no arbitrary host memory access.
- **No raw pointers**: Wasm has no concept of pointer arithmetic on host memory.
- **Controlled imports/exports**: The host explicitly chooses which functions to expose to the module.
- **Resource limits**: Execution can be metered and fuel-limited to prevent CPU exhaustion.

This makes Wasm a good fit for:
- **Plugin systems**: Load third-party extensions without trusting them.
- **Policy evaluation**: Run authorization logic in isolation (e.g., OPA-style policies).
- **Untrusted input parsing**: Parse file formats or protocol messages in a sandbox.
- **Edge computing**: Run user-provided functions on your infrastructure safely.

### 11.6.2 Compiling Rust to Wasm

```bash
# Add the Wasm target
rustup target add wasm32-unknown-unknown

# Build as Wasm
cargo build --target wasm32-unknown-unknown --release
```

For production, prefer `wasm32-wasip2` (Component Model) or `wasm32-wasip1` (WASI) targets for better system integration:

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
```

### 11.6.3 Sandboxed Plugin Architecture with Wasmtime

```toml
# Cargo.toml
[dependencies]
wasmtime = "25"
anyhow = "1"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::anyhow as anyhow;
# use rust_secure_systems_book::deps::wasmtime as wasmtime;
use wasmtime::*;
use anyhow::Result;

struct HostState {
    limits: StoreLimits,
}

fn run_untrusted_plugin(wasm_bytes: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let mut config = Config::new();
    config.cranelift_debug_verifier(true);  // Verify generated code
    config.consume_fuel(true);              // Enable deterministic CPU budgeting
    
    let engine = Engine::new(&config)?;
    let module = Module::from_binary(&engine, wasm_bytes)?;
    
    // Create a store with concrete resource limits for future growth.
    let mut store = Store::new(&engine, HostState {
        limits: StoreLimitsBuilder::new()
            .memory_size(1 << 20)  // 1 MiB
            .instances(1)
            .build(),
    });
    store.limiter(|state| &mut state.limits);
    
    // Set fuel limit to prevent infinite loops
    store.set_fuel(10_000)?;
    
    // Define only the functions the plugin is allowed to call
    let log_func = Func::wrap(&mut store, |ptr: u32, len: u32| {
        // In a real implementation, you would safely read from the
        // module's memory. This is a simplified example.
        println!("Plugin logged {} bytes at offset {}", len, ptr);
    });
    
    let instance = Instance::new(
        &mut store,
        &module,
        &[Extern::Func(log_func)],
    )?;
    
    // Call the plugin's process function
    let process = instance
        .get_typed_func::<(u32, u32), u32>(&mut store, "process")?;
    
    // Allocate input in module memory and call process
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| anyhow::anyhow!("module has no exported memory"))?;
    
    // Write input to module memory
    let mem_data = memory.data_mut(&mut store);
    if input.len() > mem_data.len() / 2 {
        return Err(anyhow::anyhow!("input too large for sandbox memory"));
    }
    mem_data[..input.len()].copy_from_slice(input);
    
    let result = process.call(&mut store, (0, input.len() as u32))?;
    
    // Read output from module memory (simplified)
    let output_len = result as usize;
    if output_len > memory.data(&store).len() {
        return Err(anyhow::anyhow!("plugin returned invalid length"));
    }
    let output = memory.data(&store)[..output_len].to_vec();
    
    Ok(output)
}
```

🔒 **Security measures in this architecture**:
1. **Fuel limiting**: Prevents infinite loops and CPU exhaustion (CWE-400, CWE-789).
2. **Resource limits**: `Store::limiter` caps future memory and instance growth.
3. **Explicit imports**: Only `log_func` is exposed—the plugin cannot access files, network, or environment variables.
4. **Input validation**: Host validates all data read from module memory before using it.

### 11.6.4 Wasm Security Considerations

| Concern | Mitigation |
|---------|------------|
| Side-channel attacks (timing, cache) | Use constant-time Wasm runtimes; consider single-threaded execution |
| Spectre-type attacks | Use a maintained Wasm runtime (for example, Wasmtime) and follow its documented Spectre mitigations |
| Resource exhaustion (memory) | Set `Store::limiter()` to cap memory growth |
| Resource exhaustion (CPU) | Use fuel metering; set timeouts on `Store` operations |
| Supply chain (malicious Wasm) | Verify Wasm module hashes or signatures before loading |
| Module size bombs | Reject modules above a size limit before compilation |
| Host function safety | Validate all arguments passed from Wasm to host functions |

⚠️ **Important**: Wasm sandboxing protects the **host** from the **module**, but it does not protect the module from itself. A compromised module's internal state is the attacker's problem—your concern is preventing the module from affecting the host or other modules.

## 11.7 Summary

- Use `#[repr(C)]` for FFI-compatible and wire-format structures.
- Use `#[repr(u8)]` / `#[repr(i32)]` to control enum size.
- Use `#[repr(align(N))]` for alignment-critical data.
- Prefer `zerocopy` crate for safe binary parsing.
- Always use explicit endianness for network data.
- Zero sensitive memory before freeing (use `zeroize` crate).
- Lock memory pages containing secrets (prevent swapping).
- Verify release hardening (RELRO/NX/PIE) and apply stack-protector flags to any C/C++ objects you compile.
- **Consider WebAssembly sandboxing** for running untrusted code, with fuel limiting, memory caps, and minimal host imports.

In the next chapter, we cover secure network programming—building network services that resist common attacks.

## 11.8 Exercises

1. **Wire-Format Parser**: Define a `#[repr(C)]` struct representing a simplified IPv4 header (version, IHL, total length, TTL, protocol, source IP, dest IP). Use the `zerocopy` crate to parse a raw byte slice into the struct. Write tests with valid packets, truncated packets, and misaligned data. Verify that all invalid inputs return an error.

2. **Endianness Trap**: Write two versions of a u32 parser: one using `from_be_bytes` and one using `from_le_bytes`. Feed both the same byte sequence `[0x00, 0x01, 0x02, 0x03]`. Verify the results differ. Then write a function that parses a TCP header from bytes using correct big-endian for all multi-byte fields.

3. **Aligned Buffer**: Create a 16-byte-aligned buffer type using `#[repr(C, align(16))]`. Implement methods to safely write and read data. Verify alignment at runtime using pointer arithmetic. Discuss why aligned buffers can matter for SIMD or DMA paths, and why AES-NI itself does not require 16-byte alignment for correctness.
