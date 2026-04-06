use std::ffi::{CStr, CString, NulError, c_char};
use std::ptr;
use std::sync::Mutex;

pub const MAX_BUFFER_SIZE: usize = 1024 * 1024;
pub const MAX_ALLOCATION: usize = MAX_BUFFER_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub enum ProcessingError {
    Empty,
    TooLarge(usize),
}

unsafe extern "C" {
    #[link_name = "book_ffi_strlen"]
    fn book_ffi_strlen_c(s: *const c_char) -> usize;
}

pub fn c_string_length(s: &CStr) -> usize {
    unsafe { book_ffi_strlen_c(s.as_ptr()) }
}

pub fn call_c_with_string(input: &str) -> Result<usize, NulError> {
    let c_string = CString::new(input)?;
    Ok(c_string_length(&c_string))
}

/// # Safety
///
/// `raw` must point to a valid, NUL-terminated C string that remains alive for
/// the duration of the returned borrow.
pub unsafe fn receive_c_string<'a>(raw: *const c_char) -> Option<&'a str> {
    if raw.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(raw).to_str().ok() }
}

/// # Safety
///
/// `raw` must point to a valid, NUL-terminated C string for the duration of
/// this call.
pub unsafe fn receive_c_string_owned(raw: *const c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(raw).to_str().ok().map(|s| s.to_owned()) }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `s` must either be null or point to a valid, NUL-terminated C string.
pub unsafe extern "C" fn book_ffi_strlen(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }

    unsafe { CStr::from_ptr(s).to_bytes().len() }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_add(a: i32, b: i32) -> i32 {
    a.checked_add(b).unwrap_or(0)
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `data` must either be null or point to `len` readable bytes for the
/// duration of this call.
pub unsafe extern "C" fn process_buffer(data: *const u8, len: usize) -> i32 {
    if data.is_null() {
        return -1;
    }
    if len > MAX_BUFFER_SIZE {
        return -2;
    }

    let result = std::panic::catch_unwind(|| {
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        process_data(slice)
    });

    match result {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => -3,
        Err(_) => -4,
    }
}

fn process_data(data: &[u8]) -> Result<i32, ProcessingError> {
    if data.is_empty() {
        return Err(ProcessingError::Empty);
    }
    if data.len() > MAX_BUFFER_SIZE {
        return Err(ProcessingError::TooLarge(data.len()));
    }
    Ok(data.len() as i32)
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiResult {
    pub success: bool,
    pub value: i64,
    pub error_code: i32,
    pub error_message: [u8; 256],
}

#[unsafe(no_mangle)]
pub extern "C" fn compute(x: i64, y: i64) -> FfiResult {
    match x.checked_mul(y) {
        Some(value) => FfiResult {
            success: true,
            value,
            error_code: 0,
            error_message: [0; 256],
        },
        None => {
            let mut msg = [0u8; 256];
            let err = b"multiplication overflow";
            msg[..err.len()].copy_from_slice(err);
            FfiResult {
                success: false,
                value: 0,
                error_code: 1,
                error_message: msg,
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn create_buffer(size: usize) -> *mut u8 {
    if size == 0 || size > MAX_ALLOCATION {
        return ptr::null_mut();
    }

    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `ptr` and `size` must come from `create_buffer`; `size` is the exact byte
/// length originally requested from `create_buffer`; and `free_buffer` must be
/// called at most once for a given allocation.
pub unsafe extern "C" fn free_buffer(ptr: *mut u8, size: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::<u8>::from_raw_parts(ptr, 0, size);
        }
    }
}

pub type Callback = extern "C" fn(i32, *const u8, usize) -> i32;

static GLOBAL_CALLBACK: Mutex<Option<Callback>> = Mutex::new(None);

#[unsafe(no_mangle)]
pub extern "C" fn register_callback(cb: Option<Callback>) -> i32 {
    register_callback_safe(cb)
}

pub fn register_callback_safe(cb: Option<Callback>) -> i32 {
    let mut guard = GLOBAL_CALLBACK.lock().expect("callback mutex poisoned");
    *guard = cb;
    0
}

pub fn invoke_registered_callback(status: i32, payload: &[u8]) -> Option<i32> {
    let callback = *GLOBAL_CALLBACK.lock().expect("callback mutex poisoned");
    callback.map(|cb| cb(status, payload.as_ptr(), payload.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn sample_callback(status: i32, _data: *const u8, len: usize) -> i32 {
        status + len as i32
    }

    #[test]
    fn string_conversion_round_trip() {
        let c_string = CString::new("hello").expect("CString");
        assert_eq!(call_c_with_string("hello"), Ok(5));
        assert_eq!(
            unsafe { receive_c_string(c_string.as_ptr()) },
            Some("hello")
        );
        assert_eq!(
            unsafe { receive_c_string_owned(c_string.as_ptr()) },
            Some("hello".to_string())
        );
    }

    #[test]
    fn exported_functions_validate_inputs() {
        assert_eq!(rust_add(i32::MAX, 1), 0);
        assert_eq!(unsafe { process_buffer(ptr::null(), 8) }, -1);
        assert_eq!(unsafe { process_buffer([1u8, 2, 3].as_ptr(), 3) }, 3);
    }

    #[test]
    fn compute_reports_overflow() {
        let ok = compute(4, 5);
        assert!(ok.success);
        assert_eq!(ok.value, 20);

        let overflow = compute(i64::MAX, 2);
        assert!(!overflow.success);
        assert_eq!(overflow.error_code, 1);
    }

    #[test]
    fn buffer_allocation_round_trip() {
        let ptr = create_buffer(16);
        assert!(!ptr.is_null());
        unsafe {
            ptr::write_bytes(ptr, 0xAA, 16);
        }
        unsafe {
            free_buffer(ptr, 16);
        }
    }

    #[test]
    fn safe_callback_registration() {
        assert_eq!(register_callback_safe(Some(sample_callback)), 0);
        assert_eq!(invoke_registered_callback(7, b"abc"), Some(10));
        assert_eq!(register_callback_safe(None), 0);
        assert_eq!(invoke_registered_callback(7, b"abc"), None);
    }
}
