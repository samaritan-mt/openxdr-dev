#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]

/**
 * Execve event structure
 * @member pid: Process ID
 * @member uid: User ID
 * @member comm: Command name
 * @member filename: Executed file name
 */
pub struct ExecveEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
}
