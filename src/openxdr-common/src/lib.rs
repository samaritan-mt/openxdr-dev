#![no_std]

/**
 * Execve event structure
 * @member pid: Process ID
 * @member uid: User ID
 * @member comm: Command name
 * @member filename: Executed file name
 */
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExecveEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 512],
    pub args: Option<[u8; 128]>,
}
/**
 * File event structure
 * @member path: File path
 * @member flags: File flags
 * @member pid: Process ID
 * @member uid: User ID
 * @member comm: Command name
 */
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileEvent {
    pub path: [u8; 128],
    pub flags: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}
