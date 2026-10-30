//! Ctrl-C and Ctrl-Break must reach the harness, not kill warden before it.

use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::core::BOOL;

unsafe extern "system" fn handler(event: u32) -> BOOL {
    // handled: warden keeps waiting; the harness shares the console and gets the event itself
    BOOL::from(event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
}

/// Install a handler that swallows Ctrl-C/Ctrl-Break in warden. A handler routine
/// is per-process and not inherited, so the child keeps the default behaviour
/// (unlike `SetConsoleCtrlHandler(NULL, TRUE)`, which children inherit).
pub fn ignore_console_interrupts() {
    // SAFETY: `handler` has the HandlerRoutine signature and lives for the process.
    unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
}
