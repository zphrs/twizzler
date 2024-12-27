//! Implements the non-arch-specific upcall handling functionality for the runtime.

use core::sync::atomic::{AtomicBool, Ordering};

use twizzler_abi::upcall::{UpcallData, UpcallFrame};

#[thread_local]
static UPCALL_PANIC: AtomicBool = AtomicBool::new(false);

#[allow(dead_code)]
pub(crate) fn upcall_rust_entry(frame: &UpcallFrame, info: &UpcallData) {
    if UPCALL_PANIC.load(Ordering::SeqCst) {
        twizzler_abi::syscall::sys_thread_exit(127);
    }
    UPCALL_PANIC.store(true, Ordering::SeqCst);
    panic!(
        "upcall ip={:x} sp={:x} :: {:?}",
        frame.ip(),
        frame.sp(),
        info
    );
}
