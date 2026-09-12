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
    maps::{PerCpuArray, PerfEventArray, Array},
    programs::TracePointContext,
    EbpfContext,
};

use openxdr_common::{
    pattern_matches, ExecveEvent, FileEvent, KernelRuleArray, LSMEvent, ModuleEvent, NetworkEvent,
    MAX_KERNEL_RULES,
};

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
static RULES_ARRAY: Array<KernelRuleArray> = Array::with_max_entries(1, 0);

#[map]
static SCRATCH: PerCpuArray<[u8; 4096]> = PerCpuArray::with_max_entries(1, 0);

/// Kernel-side rule pre-filter: does *any* loaded rule want this event?
///
/// Returns `true` to forward the event to userspace. The contract is
/// deliberately asymmetric -- every uncertain case returns `true`, because a
/// dropped event is a missed detection while an extra event only costs CPU.
#[inline(always)]
fn passes_kernel_filter<const N: usize>(event_type: u8, comm: &[u8; 16], path: &[u8; N]) -> bool {
    debug_assert!(N.is_power_of_two());

    let Some(block) = RULES_ARRAY.get(0) else {
        // Map not populated yet (agent still starting): forward everything.
        return true;
    };

    // Userspace told us this event type cannot be filtered correctly.
    if block.permissive_mask & (1u32 << (event_type & 31)) != 0 {
        return true;
    }

    let count = block.count as usize;
    if count == 0 {
        return true;
    }
    let limit = if count > MAX_KERNEL_RULES {
        MAX_KERNEL_RULES
    } else {
        count
    };

    // Measure both haystacks once, outside the rule loop. Doing this per rule
    // would multiply the scan cost by the rule count.
    let mut comm_len = 0usize;
    for i in 0..16 {
        if comm[i] == 0 {
            break;
        }
        comm_len = i + 1;
    }
    let mut path_len = 0usize;
    for i in 0..N {
        if path[i] == 0 {
            break;
        }
        path_len = i + 1;
    }

    for i in 0..MAX_KERNEL_RULES {
        if i >= limit {
            break;
        }
        let rule = &block.rules[i];

        if rule.event_type != event_type && rule.event_type != 0 {
            continue;
        }

        if rule.check_comm == 1
            && !pattern_matches(
                comm,
                comm_len,
                &rule.comm,
                rule.comm_len as usize,
                rule.comm_kind,
            )
        {
            continue;
        }

        if rule.check_path == 1
            && !pattern_matches(
                path,
                path_len,
                &rule.path,
                rule.path_len as usize,
                rule.path_kind,
            )
        {
            continue;
        }

        return true;
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
            for i in 0..8 {
                if let Ok(arg_ptr) = bpf_probe_read_user::<u64>((args_ptr + (i * 8)) as *const u64) {
                    if arg_ptr == 0 {
                        break; // NULL pointer terminates argv, avoid reading envp
                    }
                    event.argc += 1;
                    let start = (i as usize) * 128;
                    let end = start + 128;
                    match bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut event.argv[start..end]) {
                        Ok(slice) => {
                            let len = slice.len();
                            if len > 0 && len <= 128 {
                                event.argv[start + len - 1] = 0;
                            } else {
                                event.argv[start] = 0;
                            }
                        }
                        Err(_) => { event.argv[start] = 0; }
                    }
                    event.argv[end - 1] = 0; // force null termination
                } else {
                    break;
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
    let _ = try_file_open(ctx, 24, 32);
    0
}

#[tracepoint]
pub fn openat_enter(ctx: TracePointContext) -> u32 {
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

    // For FIM logic, we no longer drop pure reads. 
    // Wait, to avoid spam, we ONLY want to trace it if it matches our RULES.
    // We will do the matching AFTER we extract the filename!

    // Allocate the event in the scratch map to avoid 512-byte stack limit!
    let buf_ptr = match SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return Err(0),
    };
    let event = unsafe { &mut *(buf_ptr as *mut FileEvent) };

    event.path = [0; 128];
    event.flags = flags as u32;
    event.pid = pid;
    event.uid = uid;
    event.comm = [0; 16];

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

    // Now check if it passes the kernel filter
    // If it's a read (not a write) AND it doesn't match a rule, we drop it to avoid spam.
    let is_write = (flags & 0b11) != 0
        || (flags & 0o100) != 0
        || (flags & 0o1000) != 0
        || (flags & 0o2000) != 0;

    if !passes_kernel_filter(2, &event.comm, &event.path) {
        if !is_write {
            // Drop pure reads that do not explicitly match a FIM rule
            return Ok(0);
        }
    }

    EVENTS_FILE.output(&ctx, event, 0);
    Ok(0)
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check(ctx: LsmContext) -> i32 {
    match try_bprm_check(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
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

#[repr(C)]
pub struct in6_addr {
    pub in6_u: [u8; 16],
}

#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[tracepoint]
pub fn connect_enter(ctx: TracePointContext) -> i32 {
    match try_connect_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_connect_enter(ctx: TracePointContext) -> Result<i32, i32> {
    // Arg 0 (sockfd) is at offset 16, Arg 1 (addr ptr) is at offset 24
    let fd: i32 = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) as i32 };
    let uservaddr: *const sockaddr = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) as *const sockaddr };

    let sa = match unsafe { bpf_probe_read_user(uservaddr as *const sockaddr) } {
        Ok(sa) => sa,
        Err(_) => return Ok(0),
    };

    if sa.sa_family != 2 && sa.sa_family != 10 { // AF_INET or AF_INET6
        return Ok(0);
    }

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
    event.daddr = [0; 16];

    if sa.sa_family == 2 {
        let sin = match unsafe { bpf_probe_read_user(uservaddr as *const sockaddr_in) } {
            Ok(sin) => sin,
            Err(_) => return Ok(0),
        };
        event.is_ipv6 = 0;
        event.dport = sin.sin_port;
        let ipv4_bytes = sin.sin_addr.s_addr.to_ne_bytes();
        event.daddr[..4].copy_from_slice(&ipv4_bytes);
    } else {
        let sin6 = match unsafe { bpf_probe_read_user(uservaddr as *const sockaddr_in6) } {
            Ok(sin6) => sin6,
            Err(_) => return Ok(0),
        };
        event.is_ipv6 = 1;
        event.dport = sin6.sin6_port;
        event.daddr.copy_from_slice(&sin6.sin6_addr.in6_u);
    }

    EVENTS_NET.output(&ctx, event, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

