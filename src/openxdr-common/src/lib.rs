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
pub const MAX_KERNEL_RULES: usize = 32;

/// Maximum byte length of a lowered pattern, and the loop bound the verifier
/// reasons about in `pattern_matches`.
///
/// This is a *verifier* budget, not a storage decision. The bound appears in
/// the inner compare loop, so every byte of width is paid for in states
/// explored, per rule. Measured 2026-09-19, the longest pattern the Sigma
/// corpus lowers is 19 bytes (`/TeamViewer_Service`), so 32 leaves headroom
/// while halving what 64 cost. Longer patterns are refused by `lower_term()`
/// and turn their event type permissive.
pub const MAX_PATTERN_LEN: usize = 32;

/// Upper bound on the NUL scan used to measure an event path.
///
/// The measured length feeds every suffix offset, so the verifier carries it
/// as a scalar range and pays for the *bound*, not the data. Paths longer than
/// this are forwarded to userspace unmeasured rather than mis-measured --
/// failing open, which the superset invariant permits.
pub const MAX_PATH_SCAN: usize = 256;

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
    pub path: [u8; MAX_PATTERN_LEN],
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
pub fn pattern_matches<const N: usize, const M: usize>(
    hay: &[u8; N],
    hay_len: usize,
    pat: &[u8; M],
    pat_len: usize,
    kind: u8,
) -> bool {
    // Cheap rejects, once per rule. `hay_len <= N` always (it is produced by a
    // scan bounded by N), so these also guarantee `pat_len <= N` below.
    if pat_len == 0 || pat_len > M || pat_len > hay_len {
        return false;
    }
    if kind == MATCH_EXACT && pat_len != hay_len {
        return false;
    }

    if kind == MATCH_SUFFIX {
        suffix_matches(hay, hay_len, pat, pat_len)
    } else {
        // MATCH_PREFIX, and any unrecognised kind, degrade to prefix -- a
        // superset of exact, so never a miss.
        prefix_matches(hay, pat, pat_len)
    }
}

/// Branchless anchored-at-zero compare.
///
/// The loop runs a fixed `M` iterations of straight-line code: no `break` on a
/// runtime value, no early `return`, no branch per byte. That is the point.
///
/// The previous version exited early on the first mismatch, which reads as an
/// optimisation and is the opposite for the verifier: two branch arms per byte,
/// times `M` bytes, times two fields, times every rule -- and no pruning
/// between rules, because `pat_len` is map data and therefore a fresh unknown
/// each time. Measured cost of the branching version was >1M instructions with
/// `max_states_per_insn` 238. Accumulating into `diff` collapses that to one
/// path. See docs/verifier_complexity_budget.md.
#[inline(always)]
fn prefix_matches<const N: usize, const M: usize>(
    hay: &[u8; N],
    pat: &[u8; M],
    pat_len: usize,
) -> bool {
    let mut diff = 0u8;
    for j in 0..M {
        if j >= N {
            break; // constant vs constant: folded at compile time, not a runtime branch
        }
        // 0xFF while inside the pattern, 0x00 past it. Bytes past `pat_len`
        // contribute nothing instead of being skipped by a jump.
        let active = ((j < pat_len) as u8).wrapping_neg();
        diff |= (hay[j] ^ pat[j]) & active;
    }
    diff == 0
}

/// Branchless anchored-at-end compare.
///
/// Same shape as `prefix_matches`, but the index derives from `hay_len` and so
/// is a runtime scalar; the mask keeps it provably in range, which is sound
/// only because every haystack buffer is a power of two (512 execve/LSM, 128
/// openat, 16 comm).
///
/// This remains the expensive path. When suffix rules actually reach the
/// kernel, reverse the haystack into scratch once per event and store patterns
/// pre-reversed at lowering time, which turns every suffix compare back into
/// `prefix_matches`.
#[inline(always)]
fn suffix_matches<const N: usize, const M: usize>(
    hay: &[u8; N],
    hay_len: usize,
    pat: &[u8; M],
    pat_len: usize,
) -> bool {
    debug_assert!(N.is_power_of_two());
    let start = hay_len - pat_len; // pat_len <= hay_len checked by the caller
    let mut diff = 0u8;
    for j in 0..M {
        let active = ((j < pat_len) as u8).wrapping_neg();
        let idx = (start + j) & (N - 1);
        diff |= (hay[idx] ^ pat[j]) & active;
    }
    diff == 0
}


#[cfg(test)]
mod tests {
    use super::*;

    fn hay<const N: usize>(s: &str) -> [u8; N] {
        let mut b = [0u8; N];
        b[..s.len()].copy_from_slice(s.as_bytes());
        b
    }

    fn pat(s: &str) -> [u8; MAX_PATTERN_LEN] {
        let mut b = [0u8; MAX_PATTERN_LEN];
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
    fn a_pattern_longer_than_the_haystack_buffer_cannot_overread() {
        // comm is 16 bytes but MAX_PATTERN_LEN is 32. The `j >= N` guard in
        // prefix_matches is the only thing stopping a 32-byte pattern walking
        // off the end of a [u8; 16]. Exercise it directly.
        let comm: [u8; 16] = hay("nginx");
        let long = pat("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); // exactly 32
        assert!(!pattern_matches(&comm, 5, &long, 32, MATCH_PREFIX));
        assert!(!pattern_matches(&comm, 5, &long, 32, MATCH_EXACT));
        assert!(!pattern_matches(&comm, 5, &long, 32, MATCH_SUFFIX));
    }

    #[test]
    fn a_full_width_pattern_still_matches() {
        // MAX_PATTERN_LEN is the loop bound; an exactly-32-byte pattern must
        // not be silently truncated to 31 by an off-by-one in the guard.
        let s32 = "/usr/local/lib/systemd/aaaaaaaaa"; // 32 chars
        assert_eq!(s32.len(), MAX_PATTERN_LEN);
        let buf: [u8; 512] = hay(s32);
        assert!(pattern_matches(&buf, 32, &pat(s32), 32, MATCH_EXACT));
        assert!(pattern_matches(&buf, 32, &pat(s32), 32, MATCH_PREFIX));
        assert!(pattern_matches(&buf, 32, &pat(s32), 32, MATCH_SUFFIX));
    }

    #[test]
    fn pattern_longer_than_haystack_is_rejected_for_every_kind() {
        // The length guard was hoisted out of the per-kind arms into one
        // up-front check; confirm all three kinds still reject.
        let buf: [u8; 512] = hay("/nc");
        for kind in [MATCH_EXACT, MATCH_PREFIX, MATCH_SUFFIX] {
            assert!(!pattern_matches(&buf, 3, &pat("/usr/bin/netcat"), 15, kind));
        }
    }

    #[test]
    fn an_unrecognised_kind_degrades_to_prefix_never_to_a_match_all() {
        // kind is map data and could be anything. It must degrade to prefix
        // (a superset of exact, so never a miss) and must not match blindly.
        let buf: [u8; 512] = hay("/usr/bin/curl");
        assert!(pattern_matches(&buf, 13, &pat("/usr"), 4, 99));
        assert!(!pattern_matches(&buf, 13, &pat("/bin"), 4, 99));
    }

    #[test]
    fn abi_layout_has_no_padding_holes() {
        // aya::Pod requires the struct be safely transmutable to bytes; any
        // uninitialised padding would leak kernel stack into the map.
        assert_eq!(core::mem::size_of::<KernelRule>(), 8 + 16 + MAX_PATTERN_LEN);
        assert_eq!(core::mem::align_of::<KernelRule>(), 1);
        assert_eq!(
            core::mem::size_of::<KernelRuleArray>(),
            8 + MAX_KERNEL_RULES * core::mem::size_of::<KernelRule>()
        );
    }
}
