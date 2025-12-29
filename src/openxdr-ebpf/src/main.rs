#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    helpers::bpf_get_current_uid_gid,
    helpers::bpf_printk,
    helpers::bpf_probe_read_kernel_str_bytes,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    EbpfContext,
};

use openxdr_common::ExecveEvent;

#[map]
static EVENTS: PerfEventArray<ExecveEvent> = PerfEventArray::new(0);

/**
 * Program entry point for `execve` syscall monitoring.
 *
 * This function attaches to the `sys_enter_execve` tracepoint.
 * It delegates the processing to `try_execve_enter` with the appropriate offset
 * for the filename argument.
 *
 * # Parameters
 * * `ctx`: The tracepoint context provided by the kernel.
 *
 * # Returns
 * * `u32`: 0 on success (always returns 0).
 */
#[tracepoint]
pub fn execve_enter(ctx: TracePointContext) -> u32 {
    let _ = try_execve_enter(ctx, 16);
    0
}

/**
 * Program entry point for `execveat` syscall monitoring.
 *
 * This function attaches to the `sys_enter_execveat` tracepoint.
 * It delegates the processing to `try_execve_enter` with the appropriate offset
 * for the filename argument.
 *
 * # Parameters
 * * `ctx`: The tracepoint context provided by the kernel.
 *
 * # Returns
 * * `u32`: 0 on success (always returns 0).
 */
#[tracepoint]
pub fn execveat_enter(ctx: TracePointContext) -> u32 {
    let _ = try_execve_enter(ctx, 24);
    0
}

/**
 * Program entry point for `execve` syscall monitoring.
 *
 * This function attaches to the `sys_exit_execve` tracepoint.
 * It delegates the processing to `try_execve_exit` with the appropriate offset
 * for the filename argument.
 *
 * # Parameters
 * * `ctx`: The tracepoint context provided by the kernel.
 *
 * # Returns
 * * `u32`: 0 on success (always returns 0).
 */

/**
 * Core logic for executing execution event monitoring.
 *
 * This function retrieves the process ID, user ID, command name, and filename
 * from the tracepoint context. It handles reading the filename from potentially
 * different memory spaces (User vs Kernel) to ensure resilience.
 *
 * # Parameters
 * * `ctx`: The tracepoint context.
 * * `filename_offset`: The byte offset in the tracepoint arguments where the filename pointer is located.
 *
 * # Returns
 * * `Result<u32, u32>`: Ok(0) on success, or an error code.
 */
#[inline(always)]
fn try_execve_enter(ctx: TracePointContext, filename_offset: usize) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid >> 32) as u32;

    unsafe {
        match bpf_printk!(b"exec entry: pid %u uid %u\0", pid as u64, uid as u64) {
            _ => {}
        }
    }

    let mut event = ExecveEvent {
        pid: pid,
        uid: uid,
        comm: [0; 16],
        filename: [0; 128],
    };

    if let Ok(comm) = ctx.command() {
        let len = comm.len().min(16);
        event.comm[..len].copy_from_slice(&comm[..len]);
    } else {
        let _ = unsafe { bpf_printk!(b"failed to read command name\0") };
    }

    unsafe {
        let filename_ptr: u64 = ctx.read_at(filename_offset).unwrap_or(0);
        let _ = bpf_printk!(b"filename_ptr: 0x%lx\0", filename_ptr);

        if filename_ptr != 0 {
            let msb_set = (filename_ptr & (1 << 63)) != 0;

            if msb_set {
                match bpf_probe_read_kernel_str_bytes(
                    filename_ptr as *const u8,
                    &mut event.filename,
                ) {
                    Ok(len) => {
                        let _ = bpf_printk!(b"kernel read success, len: %u\0", len.len() as u64);
                    }
                    Err(e) => {
                        let _ = bpf_printk!(b"kernel read failed: %ld\0", e);
                    }
                }
            } else {
                if let Ok(len) =
                    bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
                {
                    let _ = bpf_printk!(b"user read success, len: %u\0", len.len() as u64);
                } else {
                    match bpf_probe_read_kernel_str_bytes(
                        filename_ptr as *const u8,
                        &mut event.filename,
                    ) {
                        Ok(len) => {
                            let _ = bpf_printk!(
                                b"fallback kernel read success, len: %u\0",
                                len.len() as u64
                            );
                        }
                        Err(e) => {
                            let _ = bpf_printk!(b"fallback kernel read failed: %ld\0", e);
                        }
                    }
                }
            }
        } else {
            let _ = bpf_printk!(b"filename_ptr is null\0");
        }
    }

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

/**
 * Try Execve Exit
 */
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
