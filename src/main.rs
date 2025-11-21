// Bidiak Mykhailo
// A minimal grep-like utility using Hyperscan for regex matching.

#![deny(warnings, clippy::all, clippy::perf)]

// External crates
use anyhow::{Context, Result, anyhow};

use std::{
    env,
    ffi::{CStr, CString},
    io::{self, BufRead},
    os::raw::{c_char, c_int, c_uint, c_void},
    process, ptr,
};

// Hyperscan FFI bindings
use hyperscan_sys as hs;

// Callback invoked by Hyperscan on a match.
// Parameters:
// - id: The pattern ID that matched.
// - from: The start offset of the match.
// - to: The end offset of the match.
// - flags: Match flags.W
// - ctx: User-defined context pointer.
// Returns 0 to continue scanning, non-zero to stop.
extern "C" fn on_match(
    _id: c_uint,
    _from: u64,
    _to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    unsafe {
        let matched = &mut *(ctx as *mut bool);
        *matched = true;
    }

    0 // 0 → continue scanning
}

// Compile a regex pattern into a Hyperscan database.
// - pattern: The regex pattern to compile.
// Returns a pointer to the database on success.
fn compile_database(pattern: &str) -> Result<*mut hs::hs_database_t> {
    let pat_c = CString::new(pattern).map_err(|_| anyhow!("pattern contains interior NUL"))?;

    let mut db: *mut hs::hs_database_t = ptr::null_mut();
    let mut err: *mut hs::hs_compile_error_t = ptr::null_mut();

    // Calls Hyperscan to compile the pattern.
    let result = unsafe {
        hs::hs_compile(
            pat_c.as_ptr(),
            0,
            hs::HS_MODE_BLOCK,
            ptr::null(),
            &mut db,
            &mut err,
        )
    };

    // Check for compilation errors.
    if result != hs::HS_SUCCESS as i32 {
        let msg = unsafe {
            if !err.is_null() && !(*err).message.is_null() {
                CStr::from_ptr((*err).message)
                    .to_string_lossy()
                    .into_owned()
            } else {
                "Unknown compile error".to_string()
            }
        };

        // Free the compile error structure.
        unsafe { hs::hs_free_compile_error(err) };

        return Err(anyhow!("Hyperscan compile error: {msg}"));
    }

    Ok(db)
}

// Allocate scratch space for scanning.
// - db: Pointer to the compiled Hyperscan database.
// Returns a pointer to the scratch space on success.
fn alloc_scratch(db: *mut hs::hs_database_t) -> Result<*mut hs::hs_scratch_t> {
    let mut scratch: *mut hs::hs_scratch_t = ptr::null_mut();

    // Calls Hyperscan to allocate scratch space.
    let result = unsafe { hs::hs_alloc_scratch(db, &mut scratch) };

    if result != hs::HS_SUCCESS as i32 {
        return Err(anyhow!(
            "Failed: Unable to allocate Hyperscan scratch (rc = {result})"
        ));
    }

    Ok(scratch)
}

// Scan a line of text using the given Hyperscan database and scratch space.
// - db: Pointer to the compiled Hyperscan database.
// - scratch: Pointer to the allocated scratch space.
// - line: The line of text to scan.
// Returns true if a match was found.
fn scan_line(
    db: *mut hs::hs_database_t,
    scratch: *mut hs::hs_scratch_t,
    line: &str,
) -> Result<bool> {
    let mut matched: bool = false;

    let result: i32 = unsafe {
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

    if result != hs::HS_SUCCESS as i32 {
        return Err(anyhow!("hs_scan failed (rc={result})"));
    }

    Ok(matched)
}

fn main() -> Result<()> {
    // Get the regex pattern from command-line arguments.
    // Pattern is expected as the first argument.
    // If not provided, print usage and exit.
    // Example usage:
    // ```type emails.txt | minigrep_hw.exe "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"```
    let pattern: String = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!(
                "Usage:\n  type file.txt | minigrep_hw.exe \"<regex>\"\nExample:\n  type emails.txt | minigrep_hw.exe \"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}$\""
            );
            process::exit(1);
        }
    };

    let database = compile_database(&pattern).context("compile pattern")?;
    let scratch = alloc_scratch(database).context("alloc scratch")?;

    let stdin = io::stdin();

    // Read lines from stdin and scan each line.
    // Print lines that match the regex pattern.
    for line in stdin.lock().lines() {
        let line: String = line?;
        if scan_line(database, scratch, &line)? {
            println!("{line}");
        }
    }

    // Free Hyperscan resources we allocated.
    unsafe {
        hs::hs_free_scratch(scratch);
        hs::hs_free_database(database);
    }

    Ok(())
}
