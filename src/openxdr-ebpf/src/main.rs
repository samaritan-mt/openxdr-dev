#![no_std]
#![no_main]

use aya_ebpf::bpf_printk;
use aya_ebpf::programs::LsmContext;
use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint},
    maps::{PerCpuArray, PerfEventArray, HashMap},
    programs::TracePointContext,
    EbpfContext,
};

use openxdr_common::{ExecveEvent, FileEvent, LSMEvent, ModuleEvent, KernelRule, NetworkEvent};

#[map]
static EVENTS: PerfEventArray<ExecveEvent> = PerfEventArray::new(0);

#[map]
static EVENTS_FILE: PerfEventArray<FileEvent> = PerfEventArray::new(0);

#[map]
static EVENTS_LSM: PerfEventArray<LSMEvent> = PerfEventArray::new(0);

#[map]
static EVENTS_MODULE: PerfEventArray<ModuleEvent> = PerfEventArray::new(0);

#[map]
static EVENTS_NET: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

#[map]
static RULES: HashMap<u32, KernelRule> = HashMap::with_max_entries(512, 0);

#[map]
static SCRATCH: PerCpuArray<[u8; 4096]> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn passes_kernel_filter(event_type: u8, comm: &[u8; 16], path: &[u8; 512]) -> bool {
    let rule0 = unsafe { RULES.get(&0) };
    if rule0.is_none() {
        return true; // fail-open if no rules loaded
    }
    
    for i in 0..512 {
        if let Some(rule) = unsafe { RULES.get(&i) } {
            if rule.event_type != event_type && rule.event_type != 0 {
                continue;
            }
            
            let mut matches = true;
            
            if rule.check_comm == 1 {
                for j in 0..16 {
                    if comm[j] != rule.comm[j] {
                        matches = false;
                        break;
                    }
                    if comm[j] == 0 { break; }
                }
            }
            
            if matches && rule.check_path == 1 {
                for j in 0..64 {
                    if rule.path[j] == 0 { break; } 
                    if path[j] != rule.path[j] {
                        matches = false;
                        break;
                    }
                }
            }
            
            if matches {
                return true;
            }
        } else {
            break; // missing index means no more rules
        }
    }
    
    false
}

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
    // 1. Get access to the scratch buffer to avoid stack allocation of the large ExecveEvent
    let buf_ptr = match SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => {
            unsafe {
                let _ = bpf_printk!(b"ERROR: SCRATCH lookup failed\0");
            }
            return Err(0);
        }
    };

    // 2. Cast the scratch buffer to our event struct
    // Safety: SCRATCH is 4096 bytes, ExecveEvent is ~670 bytes. alignment should be sufficient.
    let event = unsafe { &mut *(buf_ptr as *mut ExecveEvent) };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid >> 32) as u32;

    unsafe {
        let _ = bpf_printk!(
            b"exec entry: pid %u uid %u\0",
            event.pid as u64,
            event.uid as u64
        );
    }

    // Clear fields that might have old data from previous runs (since it's a shared per-cpu buffer)
    // We don't need to zero the whole arrays if we track length, but for safety/simplicity:
    event.comm = [0; 16];
    event.filename = [0; 512];
    event.argv = [0u8; openxdr_common::EXECVE_ARGV_BUF_SIZE];
    event.argv_truncated = 0;
    event.argc = 0;

    if let Ok(comm) = ctx.command() {
        let len = comm.len().min(16);
        event.comm[..len].copy_from_slice(&comm[..len]);
    }

    unsafe {
        let filename_ptr: u64 = ctx.read_at(filename_offset).unwrap_or(0);
        let args_ptr: u64 = ctx.read_at(filename_offset + 8).unwrap_or(0);

        // argv[0] → event.filename fallback (overwritten by filename_ptr below if valid)
        if args_ptr != 0 {
            match bpf_probe_read_user(args_ptr as *const u64) {
                Ok(arg0_ptr) if arg0_ptr != 0 => {
                    let _ = bpf_probe_read_user_str_bytes(arg0_ptr as *const u8, &mut event.filename);
                }
                Err(_) => {
                    if let Ok(arg0_ptr) = bpf_probe_read_kernel(args_ptr as *const u64) {
                        if arg0_ptr != 0 {
                            let _ = bpf_probe_read_kernel_str_bytes(arg0_ptr as *const u8, &mut event.filename);
                        }
                    }
                }
                _ => {}
            }

            // Explicit fixed reads for argv[0] to argv[7]
            // Fixed-section layout: each arg occupies exactly 128 bytes.
            // This is extremely verifier-friendly and prevents state explosion.
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[0..128]);
                    event.argv[127] = 0; // force null termination
                }
            }
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + 8) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[128..256]);
                    event.argv[255] = 0;
                }
            }
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + 16) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[256..384]);
                    event.argv[383] = 0;
                }
            }
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + 24) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[384..512]);
                    event.argv[511] = 0;
                }
            }
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + 32) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[512..640]);
                    event.argv[639] = 0;
                }
            }
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + 40) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[640..768]);
                    event.argv[767] = 0;
                }
            }
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + 48) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[768..896]);
                    event.argv[895] = 0;
                }
            }
            if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + 56) as *const u64) {
                if arg_ptr != 0 {
                    event.argc += 1;
                    let _ = bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[896..1024]);
                    event.argv[1023] = 0;
                }
            }
        }

        if filename_ptr != 0 {
            let msb_set = (filename_ptr & (1 << 63)) != 0;
            if msb_set {
                let _ =
                    bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, &mut event.filename);
            } else {
                if bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
                    .is_err()
                {
                    let _ = bpf_probe_read_kernel_str_bytes(
                        filename_ptr as *const u8,
                        &mut event.filename,
                    );
                }
            }
        }
    }

    if passes_kernel_filter(1, &event.comm, &event.filename) {
        EVENTS.output(&ctx, event, 0);
    }

    Ok(0)
}

#[tracepoint]
pub fn open_enter(ctx: TracePointContext) -> u32 {
    // filename @ 16, flags @ 24
    let _ = try_file_open(ctx, 24, 32);
    0
}

#[tracepoint]
pub fn openat_enter(ctx: TracePointContext) -> u32 {
    // dfd @ 16, filename @ 24, flags @ 32
    let _ = try_file_open(ctx, 24, 32);
    0
}

#[inline(always)]
fn try_file_open(
    ctx: TracePointContext,
    filename_offset: usize,
    flags_offset: usize,
) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid >> 32) as u32;

    let flags: u64 = unsafe { ctx.read_at(flags_offset).unwrap_or(0) };

    // Minimal filter to reduce noise (don't trace pure reads):
    // Check if lower bits are non-zero (WRONLY=1, RDWR=2) or other flags.
    let is_write = (flags & 0b11) != 0
        || (flags & 0o100) != 0
        || (flags & 0o1000) != 0
        || (flags & 0o2000) != 0;

    if !is_write {
        return Ok(0);
    }

    let mut event = FileEvent {
        path: [0; 128],
        flags: flags as u32,
        pid,
        uid,
        comm: [0; 16],
    };

    if let Ok(comm) = ctx.command() {
        let len = comm.len().min(16);
        event.comm[..len].copy_from_slice(&comm[..len]);
    }

    unsafe {
        let filename_ptr: u64 = ctx.read_at(filename_offset).unwrap_or(0);
        //let _ = bpf_printk!(b"File name pointer hex: 0x%lx\0", filename_ptr);
        if filename_ptr != 0 {
            // Try reading filename
            let msb_set = (filename_ptr & (1 << 63)) != 0;
            if msb_set {
                let _ = bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, &mut event.path);
            } else {
                if bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.path)
                    .is_err()
                {
                    let _ =
                        bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, &mut event.path);
                }
            }
        }
    }

    EVENTS_FILE.output(&ctx, &event, 0);
    Ok(0)
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check(ctx: LsmContext) -> i32 {
    match try_bprm_check(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bprm_check(_ctx: LsmContext) -> Result<i32, i32> {

    let buf_ptr = match SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return Err(0),
    };
    let event = unsafe { &mut *(buf_ptr as *mut LSMEvent) };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid >> 32) as u32;

    event.comm = [0; 16];
    event.filename = [0; 512];

    if let Ok(comm) = _ctx.command() {
        let len = comm.len().min(16);
        event.comm[..len].copy_from_slice(&comm[..len]);
    }

    // aya-ebpf 0.1.1 exposes linux_binprm, file, dentry as opaque zero-sized types —
    // field access requires BTF CO-RE (bpf_core_read!), not available until a later release.
    // filename is left empty; the execve tracepoint already captures the full path.

    if passes_kernel_filter(3, &event.comm, &event.filename) {
        EVENTS_LSM.output(&_ctx, event, 0);
    }
    
    Ok(0)
}
#[tracepoint]
pub fn init_module_enter(ctx: TracePointContext) -> u32 {
    let _ = try_module_event(&ctx, 0);
    0
}

#[tracepoint]
pub fn finit_module_enter(ctx: TracePointContext) -> u32 {
    let _ = try_module_event(&ctx, 1);
    0
}

#[inline(always)]
fn try_module_event(ctx: &TracePointContext, kind: u8) -> Result<u32, u32> {
    let buf_ptr = match SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return Err(0),
    };
    let event = unsafe { &mut *(buf_ptr as *mut ModuleEvent) };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid >> 32) as u32;
    event.comm = [0; 16];
    event.kind = kind;

    if let Ok(comm) = ctx.command() {
        let len = comm.len().min(16);
        event.comm[..len].copy_from_slice(&comm[..len]);
    }

    EVENTS_MODULE.output(ctx, event, 0);
    Ok(0)
}

use aya_ebpf::bindings::sockaddr;

#[repr(C)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[tracepoint]
pub fn connect_enter(ctx: TracePointContext) -> i32 {
    match try_connect_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_connect_enter(ctx: TracePointContext) -> Result<i32, i32> {
    // Arg 0 (sockfd) is at offset 16, Arg 1 (addr ptr) is at offset 24
    let fd: i32 = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) as i32 };
    let uservaddr: *const sockaddr = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) as *const sockaddr };

    let sa = match unsafe { bpf_probe_read_user(uservaddr as *const sockaddr) } {
        Ok(sa) => sa,
        Err(_) => return Ok(0),
    };

    if sa.sa_family != 2 { // AF_INET
        return Ok(0);
    }

    // Now read it as a sockaddr_in
    let sin = match unsafe { bpf_probe_read_user(uservaddr as *const sockaddr_in) } {
        Ok(sin) => sin,
        Err(_) => return Ok(0),
    };

    // Allocate the event
    let buf_ptr = match SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return Err(0),
    };
    let event = unsafe { &mut *(buf_ptr as *mut NetworkEvent) };

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = (uid_gid >> 32) as u32;

    event.comm = [0; 16];
    if let Ok(comm) = ctx.command() {
        let len = comm.len().min(16);
        event.comm[..len].copy_from_slice(&comm[..len]);
    }

    event.fd = fd;
    // Extract IP and Port (Note: they are in network byte order!)
    event.daddr = sin.sin_addr.s_addr;
    event.dport = sin.sin_port;

    EVENTS_NET.output(&ctx, event, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

