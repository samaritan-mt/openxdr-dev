#![no_std]
pub const EXECVE_ARGV_BUF_SIZE: usize = 1024;
pub const EXECVE_MAX_ARGS: usize = 12;


// Struct to define offset positions for each of the possible syscalls in different arch
pub const fn sys_arg(n: usize) -> usize { 16 + 8 * n }


#[derive(Clone, Copy, Default)]
pub struct AbiOffsets {
    pub execve_filename:    u32,
    pub execveat_filename:  u32,
    pub open_filename:      u32,
    pub open_flags:         u32,
    pub openat_filename:    u32,
    pub openat_flags:       u32,
    pub connect_fd:         u32,
    pub connect_addr:       u32,
}

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
    pub is_ipv6: u8,
    pub daddr: [u8; 16], // Destination IP (IPv4 in first 4 bytes or IPv6)
    pub dport: u16, // Destination Port
}

/// Maximum number of rules the eBPF fast-path evaluates per event.
///
/// This bound is dictated by the BPF verifier's complexity budget, not by map
/// memory: every rule costs up to 16 (comm) + 64 (path) bounded byte compares,
/// so 128 rules is roughly 10k verified instructions per syscall. Userspace and
/// kernel MUST agree on this value -- see `KernelRuleArray::permissive_mask`
/// for what happens when the rule set does not fit.
pub const MAX_KERNEL_RULES: usize = 128;

/// How a `KernelRule` byte pattern is compared against an event field.
///
/// These mirror the Sigma field modifiers we are able to push into the kernel.
/// `contains` and `re` are deliberately absent: an unanchored substring search
/// is O(haystack * needle) per rule, which blows the per-syscall CPU budget.
/// Rules using them mark their event type permissive instead.
pub const MATCH_EXACT: u8 = 0;
pub const MATCH_PREFIX: u8 = 1; // Sigma `|startswith`
pub const MATCH_SUFFIX: u8 = 2; // Sigma `|endswith`

/// A single Sigma selection term lowered into a kernel-evaluable byte compare.
///
/// `comm` is matched against `bpf_get_current_comm()` (TASK_COMM_LEN = 16) and
/// `path` against the event's path buffer (execve filename / openat path).
/// A check with its `check_*` flag clear is skipped, so a rule with neither
/// flag set matches every event of its type.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct KernelRule {
    pub event_type: u8, // 1=EXECVE, 2=FILE, 3=LSM, 4=MODULE; 0 = any
    pub check_comm: u8,
    pub comm_kind: u8, // MATCH_*
    pub comm_len: u8,  // pattern length, required for suffix compares
    pub check_path: u8,
    pub path_kind: u8, // MATCH_*
    pub path_len: u8,  // pattern length, required for suffix compares
    pub _pad: u8,
    pub comm: [u8; 16],
    pub path: [u8; 64],
}

/// The whole rule set, transferred as one `Array` map value so the kernel needs
/// exactly one `bpf_map_lookup_elem` per event instead of one per rule.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct KernelRuleArray {
    pub count: u32,
    /// Bit `n` set means event type `n` cannot be safely filtered in the kernel
    /// and must always be passed to userspace. Userspace sets a bit whenever a
    /// Sigma rule for that type uses a modifier we cannot lower (`contains`,
    /// `re`), has a selection branch with no pushable field, or when the type's
    /// rules overflow `MAX_KERNEL_RULES`. Failing open here trades CPU for
    /// detection coverage, which is the only acceptable direction.
    pub permissive_mask: u32,
    pub rules: [KernelRule; MAX_KERNEL_RULES],
}
/// Compare a fixed pattern against a bounded event buffer.
///
/// `N` must be a power of two so the suffix offset can be masked into range;
/// the verifier cannot prove a dynamic index is in bounds otherwise. Both
/// callers pass power-of-two buffers (512 for execve/LSM, 128 for openat),
/// which `debug_assert` guards at build time.
#[inline(always)]
pub fn pattern_matches<const N: usize>(
    hay: &[u8; N],
    hay_len: usize,
    pat: &[u8],
    pat_len: usize,
    kind: u8,
) -> bool {
    if pat_len == 0 || pat_len > pat.len() {
        return false;
    }

    // Offset of the first haystack byte to compare.
    let start = match kind {
        MATCH_SUFFIX => {
            if pat_len > hay_len {
                return false;
            }
            hay_len - pat_len
        }
        MATCH_EXACT => {
            if pat_len != hay_len {
                return false;
            }
            0
        }
        // MATCH_PREFIX and anything unrecognised degrade to a prefix compare,
        // which is a superset of exact -- never a miss.
        _ => {
            if pat_len > hay_len {
                return false;
            }
            0
        }
    };

    for j in 0..64 {
        if j >= pat_len {
            break;
        }
        // Masking keeps the index provably inside `hay` for the verifier.
        let idx = (start + j) & (N - 1);
        if hay[idx] != pat[j] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hay<const N: usize>(s: &str) -> [u8; N] {
        let mut b = [0u8; N];
        b[..s.len()].copy_from_slice(s.as_bytes());
        b
    }

    fn pat(s: &str) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..s.len()].copy_from_slice(s.as_bytes());
        b
    }

    fn run(h: &str, p: &str, kind: u8) -> bool {
        let buf: [u8; 512] = hay(h);
        pattern_matches(&buf, h.len(), &pat(p), p.len(), kind)
    }

    #[test]
    fn suffix_is_anchored_at_the_end() {
        // The bug this replaces: `*/curl` was stripped to `curl` and matched
        // anywhere, so /usr/bin/curlx and /curl/evil both passed.
        assert!(run("/usr/bin/curl", "/curl", MATCH_SUFFIX));
        assert!(!run("/usr/bin/curlx", "/curl", MATCH_SUFFIX));
        assert!(!run("/curl/evil", "/curl", MATCH_SUFFIX));
        assert!(!run("/usr/bin/curl", "/wget", MATCH_SUFFIX));
    }

    #[test]
    fn prefix_is_anchored_at_the_start() {
        assert!(run("/tmp/dropper", "/tmp/", MATCH_PREFIX));
        assert!(!run("/var/tmp/dropper", "/tmp/", MATCH_PREFIX));
    }

    #[test]
    fn exact_requires_equal_length() {
        assert!(run("/etc/passwd", "/etc/passwd", MATCH_EXACT));
        assert!(!run("/etc/passwd-", "/etc/passwd", MATCH_EXACT));
        assert!(!run("/etc/passwd", "/etc/pass", MATCH_EXACT));
    }

    #[test]
    fn pattern_longer_than_haystack_never_matches() {
        assert!(!run("/nc", "/usr/bin/netcat", MATCH_SUFFIX));
        assert!(!run("/nc", "/usr/bin/netcat", MATCH_PREFIX));
    }

    #[test]
    fn empty_pattern_is_rejected_rather_than_matching_everything() {
        assert!(!run("/usr/bin/curl", "", MATCH_SUFFIX));
        assert!(!run("", "", MATCH_EXACT));
    }

    #[test]
    fn suffix_spanning_the_whole_haystack() {
        assert!(run("/curl", "/curl", MATCH_SUFFIX));
    }

    #[test]
    fn works_on_the_128_byte_openat_buffer() {
        let buf: [u8; 128] = hay("/etc/shadow");
        assert!(pattern_matches(
            &buf,
            "/etc/shadow".len(),
            &pat("/etc/shadow"),
            11,
            MATCH_EXACT
        ));
        assert!(pattern_matches(&buf, 11, &pat("/shadow"), 7, MATCH_SUFFIX));
    }

    #[test]
    fn abi_layout_has_no_padding_holes() {
        // aya::Pod requires the struct be safely transmutable to bytes; any
        // uninitialised padding would leak kernel stack into the map.
        assert_eq!(core::mem::size_of::<KernelRule>(), 8 + 16 + 64);
        assert_eq!(core::mem::align_of::<KernelRule>(), 1);
        assert_eq!(
            core::mem::size_of::<KernelRuleArray>(),
            8 + MAX_KERNEL_RULES * core::mem::size_of::<KernelRule>()
        );
    }
}
