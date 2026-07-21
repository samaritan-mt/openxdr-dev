#![no_std]
pub const EXECVE_ARGV_BUF_SIZE: usize = 1024;
pub const EXECVE_MAX_ARGS: usize = 12;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExecveEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 512],
    pub argv: [u8; EXECVE_ARGV_BUF_SIZE],
    pub argv_truncated: u8,
    pub argc: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileEvent {
    pub path: [u8; 128],
    pub flags: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct LSMEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 512],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ModuleEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    // 0 = init_module, 1 = finit_module
    pub kind: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub fd: i32,
    pub daddr: u32, // Destination IP (IPv4)
    pub dport: u16, // Destination Port
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct KernelRule {
    pub event_type: u8, // 1=EXECVE, 2=FILE, 3=LSM, 4=MODULE
    pub check_comm: u8,
    pub comm: [u8; 16],
    pub check_path: u8,
    pub path: [u8; 64], // Literal exact match or prefix
}
