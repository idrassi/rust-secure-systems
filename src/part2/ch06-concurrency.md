# Chapter 6 — Fearless Concurrency

> *"Data races are not just bugs—they are security vulnerabilities."*

Concurrent programming is where most systems developers feel the most pain. In C/C++, shared mutable state protected by locks is an honor system: the compiler cannot verify that locks are acquired in the correct order, that every shared variable is protected, or that threads don't deadlock. The result is a constant stream of concurrency vulnerabilities: unsynchronized shared-state bugs (CWE-362) and higher-level logic races such as TOCTOU (CWE-367).

Rust's ownership system extends naturally to concurrency, enforcing thread safety at compile time. The compiler knows which data is shared, which is mutable, and whether synchronization is in place. This is "fearless concurrency"—not because concurrency is easy, but because the compiler catches the most dangerous mistakes before the code ever runs.

## 6.1 Thread Safety Guarantees

### 6.1.1 The `Send` and `Sync` Traits

Rust's concurrency safety rests on two marker traits:

- **`Send`**: A type is safe to *transfer ownership* to another thread.
- **`Sync`**: A type is safe to *share a reference* between threads (i.e., `&T` is `Send`).

Most types automatically implement `Send` and `Sync` if all their fields do. The compiler **rejects** code that violates these constraints:

```rust,compile_fail
use std::rc::Rc;  // Single-threaded reference counting

fn main() {
    let data = Rc::new(vec![1, 2, 3]);
    
    std::thread::spawn(move || {
        // ERROR: `Rc<Vec<i32>>` cannot be sent between threads safely
        println!("{:?}", data);
    });
}
```

`Rc<T>` is not `Send` because its reference counting is not atomic. Using `Arc<T>` (Atomic Reference Counted) instead fixes the issue:

```rust
use std::sync::Arc;

fn main() {
    let data = Arc::new(vec![1, 2, 3]);
    
    std::thread::spawn(move || {
        println!("{:?}", data);  // OK: Arc<Vec<i32>> is Send
    });
}
```

🔒 **Security impact**: The compiler prevents you from accidentally sharing non-thread-safe types across threads. In C, using a non-thread-safe allocator or data structure in a multithreaded context is a subtle and dangerous bug.

### 6.1.2 Ownership Prevents Data Races

The borrow checker's rules extend to threads:

- You can have **multiple readers** (`&T`) OR **one writer** (`&mut T`), never both.
- To have multiple writers, you must use **explicit synchronization**.

```rust
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0u64));
    let mut handles = vec![];

    for _ in 0..100 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            let mut num = counter.lock().unwrap();
            *num += 1;
            // Lock automatically released when `num` goes out of scope
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(*counter.lock().unwrap(), 100);
}
```

### 6.1.3 Scoped Threads Avoid Unnecessary `'static`

`std::thread::spawn` requires the closure to own only `'static` data because the new thread may outlive the caller. When the threads are guaranteed to finish before the current scope exits, prefer `std::thread::scope`:

```rust
use std::thread;

fn main() {
    let mut counters = [0u64; 4];

    thread::scope(|scope| {
        for counter in &mut counters {
            scope.spawn(move || {
                *counter += 1;
            });
        }
    });

    assert_eq!(counters, [1, 1, 1, 1]);
}
```

This is especially useful in parser pipelines and batch validation code: worker threads can borrow stack data safely, and the compiler guarantees they are joined before the scope returns.

## 6.2 Synchronization Primitives

### 6.2.1 `Mutex<T>` — Mutual Exclusion

`Mutex<T>` provides exclusive access to `T`. The lock guard pattern ensures the lock is always released:

> **Note**: The examples in this section use `.unwrap()` for brevity. In production security-critical code, handle mutex poisoning explicitly (see the poisoning discussion below) and avoid `.unwrap()` on `Result` types—use `.unwrap_or_else()`, `match`, or the `?` operator instead.

```rust
use std::sync::Mutex;

struct Connection;

struct Database {
    connections: Mutex<Vec<Connection>>,
}

impl Database {
    fn add_connection(&self, conn: Connection) {
        let mut conns = self.connections.lock().unwrap();
        conns.push(conn);
        // Lock released here automatically
    }
    
    fn count(&self) -> usize {
        let conns = self.connections.lock().unwrap();
        conns.len()
        // Lock released here
    }
}
```

🔒 **Security pattern**: The RAII guard pattern ensures locks are never forgotten. In C, forgetting to unlock a mutex is a common source of deadlocks and priority inversion.

⚠️ **Poisoning**: If a thread panics while holding a `Mutex`, the mutex becomes "poisoned." Subsequent `.lock()` calls return a `PoisonError`. Calling `.unwrap()` on that `Result` will panic. If you decide recovery is acceptable, you must handle `Err(poisoned)` explicitly and call `poisoned.into_inner()` to regain access to the guard. For security-critical code, consider poisoning a signal that shared state may no longer be trustworthy:

```rust
let mutex = std::sync::Mutex::new(vec![1u8, 2, 3]);

match mutex.lock() {
    Ok(guard) => {
        let _ = guard.len();
    }
    Err(_poisoned) => {
        // Decide: abort, recover, or use the potentially-corrupted data
        eprintln!("Mutex poisoned - data may be corrupted");
        std::process::abort();  // Safest option
    }
}
```

### 6.2.2 `RwLock<T>` — Read-Write Lock

`RwLock<T>` allows multiple readers OR one writer:

```rust
use std::collections::HashMap;
use std::sync::RwLock;

struct Config {
    settings: RwLock<HashMap<String, String>>,
}

impl Config {
    fn get(&self, key: &str) -> Option<String> {
        let settings = self.settings.read().unwrap();
        settings.get(key).cloned()
    }
    
    fn set(&self, key: &str, value: &str) {
        let mut settings = self.settings.write().unwrap();
        settings.insert(key.to_string(), value.to_string());
    }
}
```

### 6.2.3 Atomics

For lock-free programming, Rust provides atomic types:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

struct AtomicCounter {
    count: AtomicU64,
}

impl AtomicCounter {
    fn new() -> Self {
        AtomicCounter { count: AtomicU64::new(0) }
    }
    
    fn increment(&self) -> u64 {
        self.count.fetch_add(1, Ordering::SeqCst)
    }
    
    fn get(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}
```

🔒 **Security note**: Use `Ordering::SeqCst` (sequentially consistent) unless you can prove a weaker ordering is correct. Incorrect memory ordering can lead to subtle data races that are extremely difficult to debug. The performance difference is rarely significant for security-critical code.

### 6.2.4 `OnceLock<T>` and `LazyLock<T>` - One-Time Initialization

For lazily initialized shared state, prefer the standard library primitives over ad hoc double-checked locking:

```rust
use std::sync::{LazyLock, OnceLock};

static TRUST_ANCHORS: OnceLock<Vec<&'static str>> = OnceLock::new();
static ALLOWED_ALGORITHMS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| vec!["ed25519", "x25519"]);

fn trust_anchors() -> &'static [&'static str] {
    TRUST_ANCHORS.get_or_init(|| vec!["Corp Root CA", "Offline Recovery CA"])
}
```

`OnceLock` is ideal for values loaded once from configuration, certificates, or policy files. `LazyLock` is convenient when the initializer is fixed at compile time. Both avoid races around first-use initialization without needing an external crate.

### 6.2.5 `Condvar` - Wait for State Changes Without Spinning

Use a condition variable when threads must sleep until a predicate becomes true:

```rust
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

struct Queue {
    items: Mutex<VecDeque<Vec<u8>>>,
    available: Condvar,
}

impl Queue {
    fn push(&self, item: Vec<u8>) {
        let mut items = self.items.lock().unwrap();
        items.push_back(item);
        self.available.notify_one();
    }

    fn pop(&self) -> Vec<u8> {
        let mut items = self.items.lock().unwrap();
        while items.is_empty() {
            items = self.available.wait(items).unwrap();
        }
        items.pop_front().unwrap()
    }
}
```

Always wait in a `while` loop, not an `if`, because wakeups can be spurious and another thread may consume the resource before the current thread reacquires the lock.

## 6.3 Message Passing with Channels

Rust's channel API encourages a "do not communicate by sharing memory; share memory by communicating" approach:

```rust
use std::sync::mpsc;
use std::thread;

struct Request {
    client_id: u64,
    payload: Vec<u8>,
}

fn main() {
    let (tx, rx) = mpsc::channel::<Request>();

    // Spawn a single worker that owns the receiver
    let worker = thread::spawn(move || {
        while let Ok(req) = rx.recv() {
            println!("Processing request {} ({} bytes)", req.client_id, req.payload.len());
        }
        println!("Channel closed, worker exiting");
    });

    // Send requests from the main thread
    for i in 0..10 {
        tx.send(Request {
            client_id: i,
            payload: vec![0u8; 64],
        }).unwrap();
    }

    // Drop the sender to signal the worker to exit
    drop(tx);
    worker.join().unwrap();
}
```

⚠️ **Limitation**: `std::sync::mpsc::Receiver` is **not** `Clone`. Only one thread can receive from a standard channel. For multi-consumer patterns, use `crossbeam-channel` or `flume` instead.

A more practical example with `crossbeam-channel` for multi-worker message distribution:

```toml
# Cargo.toml
[dependencies]
crossbeam-channel = "0.5"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::crossbeam_channel as crossbeam_channel;
use crossbeam_channel::{bounded, Sender, Receiver};
use std::thread;

enum Command {
    Process(Vec<u8>),
    Shutdown,
}

fn worker(id: usize, rx: Receiver<Command>) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::Process(data) => {
                println!("Worker {} processing {} bytes", id, data.len());
            }
            Command::Shutdown => break,
        }
    }
}

fn main() {
    let (tx, rx) = bounded::<Command>(100);  // Bounded channel prevents OOM
    
    let mut handles = vec![];
    for id in 0..4 {
        let rx = rx.clone();
        handles.push(thread::spawn(move || worker(id, rx)));
    }
    
    // Send work
    for i in 0..1000 {
        tx.send(Command::Process(vec![i as u8; 64])).unwrap();
    }
    
    // Shutdown
    for _ in 0..4 {
        tx.send(Command::Shutdown).unwrap();
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
}
```

🔒 **Security pattern**: Use bounded channels to prevent unbounded memory growth (a form of denial of service). An unbounded channel allows a fast producer to exhaust memory before a slow consumer can process messages.

## 6.4 Async/Await Concurrency

For I/O-bound workloads, Rust's async/await model provides efficient concurrency without threads:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::log as log;
# use rust_secure_systems_book::deps::tokio as tokio;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::TcpListener;

# struct State;
# impl State {
#     fn new() -> Self {
#         Self
#     }
# }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:8443").await?;
    let state = Arc::new(Mutex::new(State::new()));
    
    loop {
        let (stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, state).await {
                log::error!("Error handling {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    state: Arc<Mutex<State>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Connection handling logic
    Ok(())
}
```

⚠️ **Important difference**: `tokio::sync::Mutex` (async) vs. `std::sync::Mutex` (blocking):
- Use `std::sync::Mutex` when the critical section is short and CPU-bound.
- Use `tokio::sync::Mutex` when you need to hold the lock across `.await` points.

🔒 **Security note**: `tokio::sync::Mutex` does not get poisoned on panic. This means corrupted state might continue to be used. For security-critical data, validate state after acquiring the lock.

### 6.4.1 `async fn` in Traits

Rust 1.75 stabilized `async fn` in traits, which matters for security interfaces such as authenticators, audit sinks, key stores, and policy engines:

```rust,no_run
trait Authenticator {
    async fn authenticate(&self, token: &str) -> Result<UserId, AuthError>;
}

# struct UserId(u64);
# #[derive(Debug)]
# struct AuthError;
```

This is a good fit for internal application traits where you control both callers and implementors. For public library traits, decide up front whether implementors must return `Send` futures, because that requirement becomes part of the trait's API surface and cannot be added later without a breaking change.

## 6.5 Cancellation Safety in Async Rust

One of the most subtle security pitfalls in async Rust is **cancellation safety** (sometimes called "cancel safety"). When a `tokio::select!` branch is not chosen, or a `JoinHandle` is aborted, the future at the other branch is **dropped** mid-execution. If that future was in the middle of an operation with side effects—such as reading from a socket or holding a lock—those side effects may be lost or left in an inconsistent state.

### 6.5.1 The Problem

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::tokio as tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

# fn process_message(_body: &[u8]) {}

/// WARNING: This function is NOT cancellation-safe.
async fn read_one_message_exact(stream: &mut TcpStream) -> std::io::Result<()> {
    // If we are cancelled after reading the first message header
    // but before reading its body, the stream is now in an inconsistent
    // state. The first message's bytes have been consumed, but we have
    // not processed them. Data is silently lost.
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;  // May succeed
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;     // If cancelled HERE, header bytes are gone
    process_message(&body);
    Ok(())
}
```

If `read_one_message_exact` is used inside `tokio::select!` and the other branch wins, the partial read is lost:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::tokio as tokio;
# use std::time::Duration;
# async fn read_one_message_exact(
#     _stream: &mut tokio::net::TcpStream,
# ) -> std::io::Result<()> {
#     Ok(())
# }
# async fn demo(stream: &mut tokio::net::TcpStream) {
// DANGEROUS: may silently drop partial reads
tokio::select! {
    result = read_one_message_exact(stream) => { /* ... */ }
    _ = tokio::time::sleep(Duration::from_secs(30)) => {
        // Timeout! But we may have already consumed some bytes from `stream`.
        // The stream is now in an inconsistent state.
    }
}
# }
```

🔒 **Security impact**: Cancellation-unsafe code can cause:
- **Data loss**: Partially read messages are dropped, violating protocol integrity.
- **State desynchronization**: The peer believes data was consumed; our side disagrees.
- **Protocol confusion**: The stream is now misaligned, potentially parsing attacker-controlled data as message headers (CWE-1265, CWE-20).

### 6.5.2 Making Async Code Cancellation-Safe

A function is cancellation-safe if dropping the future at any `.await` point leaves the system in a consistent state. Key patterns:

**Pattern 1: Use cancellation-safe operations.** `tokio::io::AsyncReadExt::read()` (which reads *up to* N bytes) is cancellation-safe because it either reads data or doesn't—no partial state. `read_exact()` is **not** cancellation-safe because it may have read some bytes but not all.

**Pattern 2: Buffer and retry.** Use a framed reader that buffers partial reads:

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::tokio as tokio;
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::TcpStream;

/// A buffered reader that tracks position and can resume after cancellation.
struct FramedReader {
    buffer: Vec<u8>,
    read_pos: usize,
}

impl FramedReader {
    fn new(max_size: usize) -> Self {
        FramedReader {
            buffer: vec![0u8; max_size],
            read_pos: 0,
        }
    }

    /// Cancellation-safe: reads one full message or nothing.
    /// If cancelled, `read_pos` still reflects previously consumed data.
    async fn read_message(
        &mut self,
        stream: &mut ReadHalf<TcpStream>,
    ) -> std::io::Result<Option<&[u8]>> {
        // Try to read more data (non-destructive on cancellation)
        if self.read_pos < 4 {
            let n = stream.read(&mut self.buffer[self.read_pos..]).await?;
            if n == 0 {
                return Ok(None); // EOF
            }
            self.read_pos += n;
            if self.read_pos < 4 {
                return Ok(None); // Need more data
            }
        }

        let len = u32::from_be_bytes([
            self.buffer[0], self.buffer[1], self.buffer[2], self.buffer[3]
        ]) as usize;

        if len > self.buffer.len() - 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message too large",
            ));
        }

        // Read remaining data if needed
        while self.read_pos < 4 + len {
            let n = stream.read(&mut self.buffer[self.read_pos..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-message",
                ));
            }
            self.read_pos += n;
        }

        // Consume the message
        let message_end = 4 + len;
        let message = &self.buffer[..message_end];
        // Note: caller should copy the data before calling advance()
        Ok(Some(message))
    }

    /// Call after successfully processing a message.
    fn advance(&mut self) {
        let message_end = 4 + self.current_message_len();
        let remaining = self.read_pos - message_end;
        if remaining > 0 {
            self.buffer.copy_within(message_end..self.read_pos, 0);
        }
        self.read_pos = remaining;
    }

    fn current_message_len(&self) -> usize {
        if self.read_pos < 4 {
            return 0;
        }
        u32::from_be_bytes([
            self.buffer[0], self.buffer[1], self.buffer[2], self.buffer[3]
        ]) as usize
    }
}
```

**Pattern 3: Use `tokio_util::codec` for production.** The `tokio_util::codec` framework handles framing and buffering for you, making it cancellation-safe by design:

```toml
# Cargo.toml
[dependencies]
tokio-util = { version = "0.7", features = ["codec"] }
bytes = "1"
```

```rust,no_run
# extern crate rust_secure_systems_book;
# use rust_secure_systems_book::deps::bytes as bytes;
# use rust_secure_systems_book::deps::tokio_util as tokio_util;
use tokio_util::codec::Decoder;
use bytes::{BytesMut, Buf, BufMut};

struct LengthPrefixedCodec {
    max_length: usize,
}

impl Decoder for LengthPrefixedCodec {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None); // Need more data
        }
        // Peek at the length without advancing the cursor
        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        if len > self.max_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        if src.len() < 4 + len {
            src.reserve(4 + len - src.len());
            return Ok(None); // Need more data
        }
        // Now consume the length prefix and payload
        src.advance(4);
        Ok(Some(src.split_to(len).to_vec()))
    }
}
```

🔒 **Security practice**: Always use a framed codec (`tokio_util::codec`) or equivalent buffering layer for production async network code. It ensures cancellation safety, enforces message size limits, and prevents partial-read desynchronization.

### 6.5.3 Other Async Pitfalls

| Pitfall | Description | Mitigation |
|---------|-------------|------------|
| **Task starvation** | A busy task never yields, starving others | Use `tokio::task::yield_now()` in tight loops; use cooperative budgeting |
| **Unbounded spawning** | `tokio::spawn` without limits → OOM | Use a `Semaphore` to limit concurrent tasks |
| **Blocking in async** | Calling `std::thread::sleep` or CPU-heavy work blocks the executor | Use `tokio::task::spawn_blocking` for blocking operations |
| **Aborted task cleanup** | `JoinHandle::abort()` drops the future; resources may leak | Use `Drop` guards for cleanup, or structured concurrency patterns |

## 6.6 Common Concurrency Pitfalls (and How Rust Prevents Them)

### 6.6.1 Deadlocks

Rust does **not** prevent deadlocks. If you acquire multiple locks in different orders, you can still deadlock:

```rust
use std::sync::{Arc, Mutex};

fn main() {
    let a = Arc::new(Mutex::new(0));
    let b = Arc::new(Mutex::new(0));
    
    let a1 = Arc::clone(&a);
    let b1 = Arc::clone(&b);
    let h1 = std::thread::spawn(move || {
        let _g1 = a1.lock().unwrap();
        let _g2 = b1.lock().unwrap();  // May deadlock
    });
    
    let a2 = Arc::clone(&a);
    let b2 = Arc::clone(&b);
    let h2 = std::thread::spawn(move || {
        let _g1 = b2.lock().unwrap();
        let _g2 = a2.lock().unwrap();  // May deadlock (different order!)
    });
}
```

🔒 **Mitigation**: Use a consistent lock ordering, or use a single lock to protect multiple resources. If you need timed locking or better deadlock diagnostics, `parking_lot` is a common production alternative to `std::sync`.

### 6.6.2 Use-After-Free in Concurrent Contexts

In C, passing a stack pointer to another thread is a common use-after-free:

```c
// C - DANGEROUS
void* thread_func(void* arg) {
    int* data = (int*)arg;
    sleep(1);
    printf("%d\n", *data);  // data may be freed!
}

int main() {
    int value = 42;
    pthread_t tid;
    pthread_create(&tid, NULL, thread_func, &value);
    // value goes out of scope, thread still holds a pointer!
    return 0;  // Use-after-free
}
```

Rust prevents this at compile time:

```rust,compile_fail
fn main() {
    let value = 42;
    std::thread::spawn(|| {
        // ERROR: `value` does not live long enough
        println!("{}", value);
    });
}
```

To fix, you must explicitly move the value:

```rust
fn main() {
    let value = 42;
    std::thread::spawn(move || {
        println!("{}", value);  // OK: ownership transferred
    });
}
```

## 6.7 Summary

- `Send` and `Sync` traits enforce thread safety at compile time.
- `Mutex<T>` and `RwLock<T>` provide RAII-based locking that never forgets to unlock.
- Atomics provide lock-free patterns; use `SeqCst` ordering unless you can prove weaker is safe.
- `OnceLock` and `LazyLock` provide race-free one-time initialization for shared security state.
- `Condvar` lets threads wait on predicates without busy-waiting; always re-check the condition in a loop.
- Channels enable message-passing concurrency; prefer bounded channels to prevent memory exhaustion.
- Rust prevents use-after-free in concurrent contexts but does not prevent deadlocks—use consistent lock ordering.
- Async/await is efficient for I/O-bound workloads; understand the differences between sync and async mutexes.
- **Cancellation safety** is critical in async code: always use framed codecs or buffered readers to ensure partial reads are not lost when futures are dropped.

In the next chapter, we tackle input validation—the first line of defense against injection and parsing attacks.

## 6.8 Exercises

1. **Thread Safety Verification**: Create a struct containing an `Rc<String>` and attempt to send it across a thread boundary with `std::thread::spawn`. Observe the compiler error. Replace `Rc` with `Arc` and verify it compiles. Then add a `RefCell<String>` inside the `Arc` and observe the new error when trying to share it across threads. Replace with `Mutex<String>` and verify it compiles.

2. **Bounded Channel**: Implement a producer-consumer pattern with a bounded channel of capacity 10. Spawn a fast producer that sends 100 messages and a slow consumer that sleeps for 100ms per message. Observe the backpressure behavior. Then switch to an unbounded channel and discuss the memory implications.

3. **Deadlock Demonstration**: Write a program that intentionally deadlocks by acquiring two `Mutex`es in opposite orders from two threads. Confirm the deadlock (the program hangs). Then fix it by establishing a consistent lock ordering. Add a timeout using `try_lock_for` (from `parking_lot`) to detect and recover from potential deadlocks.

4. **Cancellation Safety**: Write an async function that reads a 4-byte header followed by a variable-length body from a `TcpStream`. Use `tokio::select!` with a timeout. Demonstrate the data loss bug when using `read_exact`. Then rewrite using a `Framed` codec from `tokio_util` and verify the fix.
