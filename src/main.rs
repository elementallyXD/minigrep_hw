#![deny(warnings, clippy::all, clippy::perf)]

use anyhow::{anyhow, Context, Result};
use std::{
    env,
    ffi::{CStr, CString},
    io::{self, BufRead},
    os::raw::{c_char, c_int, c_uint, c_void},
    ptr,
};

use hyperscan_sys as hs;

/// Hyperscan match callback: set `matched = true` via `ctx` and keep scanning.
///
/// SAFETY:
/// - `ctx` is a non-null pointer we pass to `hs_scan` that points to a valid `bool`.
/// - We only write `true` and never free it here.
/// - Signature matches Hyperscan's `match_event_handler`:
///   `extern "C" fn(u32, u64, u64, u32, *mut c_void) -> i32`.
extern "C" fn on_match(
    _id: c_uint,
    _from: u64,
    _to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is &mut bool cast to *mut c_void by our `hs_scan` call.
    unsafe {
        let matched = &mut *(ctx as *mut bool);
        *matched = true;
    }
    0 // 0 → continue scanning
}

fn compile_database(pattern: &str) -> Result<*mut hs::hs_database_t> {
    let pat_c = CString::new(pattern).map_err(|_| anyhow!("pattern contains interior NUL"))?;
    let mut db: *mut hs::hs_database_t = ptr::null_mut();
    let mut err: *mut hs::hs_compile_error_t = ptr::null_mut();

    // SAFETY:
    // - `pat_c` is a valid, NUL-terminated C string.
    // - `db` and `err` are valid out-pointers per Hyperscan docs.
    // - Mode is HS_MODE_BLOCK (simplest).
    let rc = unsafe {
        hs::hs_compile(
            pat_c.as_ptr(),
            0,                     // HS_FLAGS (keep 0 → default)
            hs::HS_MODE_BLOCK,     // block-scanning mode
            ptr::null(),           // platform (null = auto)
            &mut db,
            &mut err,
        )
    };

    if rc != hs::HS_SUCCESS as i32 {
        // SAFETY: `err` (if non-null) is allocated by Hyperscan and must be freed.
        let msg = unsafe {
            if !err.is_null() && !(*err).message.is_null() {
                CStr::from_ptr((*err).message).to_string_lossy().into_owned()
            } else {
                "Unknown compile error".to_string()
            }
        };
        unsafe { hs::hs_free_compile_error(err) };
        return Err(anyhow!("Hyperscan compile error: {msg}"));
    }

    Ok(db)
}

fn alloc_scratch(db: *mut hs::hs_database_t) -> Result<*mut hs::hs_scratch_t> {
    let mut scratch: *mut hs::hs_scratch_t = ptr::null_mut();

    // SAFETY: Allocates a scratch space tied to `db`. Must be freed with `hs_free_scratch`.
    let rc = unsafe { hs::hs_alloc_scratch(db, &mut scratch) };
    if rc != hs::HS_SUCCESS as i32 {
        return Err(anyhow!("failed to allocate Hyperscan scratch (rc={rc})"));
    }
    Ok(scratch)
}

fn scan_line(db: *mut hs::hs_database_t, scratch: *mut hs::hs_scratch_t, line: &str) -> Result<bool> {
    let mut matched = false;

    // SAFETY:
    // - `db` and `scratch` were returned by Hyperscan and remain valid for the call.
    // - `line.as_ptr()` + length form a valid buffer for the duration of the call.
    // - `on_match` signature matches Hyperscan's callback type.
    // - `ctx` is `&mut matched` cast to `*mut c_void`; we only set it to true in the callback.
    let rc = unsafe {
        hs::hs_scan(
            db,
            line.as_ptr() as *const c_char,
            line.len() as u32,
            0,
            scratch,
            Some(on_match),
            (&mut matched as *mut bool).cast::<c_void>(),
        )
    };

    if rc != hs::HS_SUCCESS as i32 {
        return Err(anyhow!("hs_scan failed (rc={rc})"));
    }
    Ok(matched)
}

fn main() -> Result<()> {
    // Minimal CLI: single positional argument = regex pattern.
    let pattern = env::args().nth(1).ok_or_else(|| {
        anyhow!(
            "Usage:\n  cat file.txt | minigrep_hs \"<regex>\"\nExample:\n  cat file.txt | minigrep_hs \"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}$\""
        )
    })?;

    let db = compile_database(&pattern).context("compile pattern")?;
    let scratch = alloc_scratch(db).context("alloc scratch")?;

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if scan_line(db, scratch, &line)? {
            println!("{line}");
        }
    }

    // SAFETY: Free Hyperscan resources we allocated.
    unsafe {
        hs::hs_free_scratch(scratch);
        hs::hs_free_database(db);
    }

    Ok(())
}