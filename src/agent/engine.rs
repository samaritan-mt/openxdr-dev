use openxdr_common::{
    KernelRule, MATCH_EXACT, MATCH_PREFIX, MATCH_SUFFIX, MAX_KERNEL_RULES, MAX_PATTERN_LEN,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

/**
 * Event structure representing an audit event.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDetails<'a> {
    pub dest_ip: Cow<'a, str>,
    pub dest_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event<'a> {
    pub event_type: Cow<'a, str>,   // e.g. "EXECVE"
    pub process_name: Cow<'a, str>, // "sudo"
    pub uid: u32,
    pub user_name: Cow<'a, str>, // "root", "alice" (or "uid:1000" if you want)
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<Cow<'a, str>>, // optional, can be empty
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall: Option<Cow<'a, str>>, // e.g., "open", "write"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<Cow<'a, str>>, // e.g., "/etc/passwd"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_write: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkDetails<'a>>, // Network details if applicable
}

// Event type discriminants shared with the eBPF side. Keep in sync with the
// `passes_kernel_filter` call sites in `openxdr-ebpf/src/main.rs`.
const ET_EXECVE: u8 = 1;
const ET_FILE: u8 = 2;
const ET_LSM: u8 = 3;
const ET_MODULE: u8 = 4;
const ET_NETWORK: u8 = 5;

type SyslogWriter = syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>;

/// Where a Sigma field is lowered to on the kernel side.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Slot {
    /// Compared against `bpf_get_current_comm()` (16 bytes).
    Comm,
    /// Compared against the event's path buffer (execve filename / openat path).
    Path,
}

/// One Sigma value lowered to a kernel byte pattern.
struct Term {
    value: String,
    kind: u8,
}

/// Why a rule could not be pushed into the kernel, for the startup report.
struct Pushdown {
    terms: Vec<Term>,
    slot: Slot,
    /// Set when the rule must fall back to userspace-only evaluation.
    permissive_reason: Option<String>,
}

pub struct Engine {
    sigma_engine: null_sigma::engine::SigmaEngine,
    kernel_rules: Vec<KernelRule>,
    permissive_mask: u32,
    /// Human-readable explanation of every permissive bit, printed at startup.
    permissive_notes: Vec<String>,
    /// Opened once and reused. `None` means syslog is unavailable; the next
    /// alert retries the connection.
    syslog: Mutex<Option<SyslogWriter>>,
}

impl Engine {
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Self {
        let mut sigma_engine = null_sigma::engine::SigmaEngine::new();
        let mut kernel_rules: Vec<KernelRule> = Vec::new();
        let mut permissive_mask: u32 = 0;
        let mut permissive_notes: Vec<String> = Vec::new();

        // The LSM probe cannot populate `filename` yet (it needs BTF CO-RE to
        // walk linux_binprm -> file -> dentry), and module/network events are
        // low volume and unfiltered. Nothing to gain, and a lot to lose, from
        // filtering them in the kernel.
        for et in [ET_MODULE, ET_NETWORK] {
            permissive_mask |= 1 << et;
        }

        if let Ok(entries) = fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|s| s.to_str()) != Some("yml") {
                    continue;
                }
                let Ok(content) = fs::read_to_string(entry.path()) else {
                    continue;
                };

                // 1. Load into the Sigma engine -- this is the authoritative
                //    matcher. The kernel fast-path below is only ever allowed
                //    to be a superset of what Sigma would accept.
                if let Err(e) = sigma_engine.load_rule(&content) {
                    eprintln!("Failed to load rule {:?}: {:?}", entry.path(), e);
                    continue;
                }

                let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
                    continue;
                };
                let name = entry
                    .path()
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                let event_type = classify_event_type(&yaml);
                if event_type == 0 {
                    continue; // Unknown logsource: no probe emits it, nothing to filter.
                }
                if permissive_mask & (1 << event_type) != 0 {
                    continue; // Type already fails open; extracting terms is pointless.
                }

                let pushdown = extract_pushdown(&yaml, event_type);
                if let Some(reason) = pushdown.permissive_reason {
                    permissive_mask |= 1 << event_type;
                    permissive_notes.push(format!("{} ({})", name, reason));
                    continue;
                }

                for term in &pushdown.terms {
                    match lower_term(event_type, pushdown.slot, term) {
                        Some(kr) => kernel_rules.push(kr),
                        None => {
                            permissive_mask |= 1 << event_type;
                            permissive_notes
                                .push(format!("{} (pattern too long: {:?})", name, term.value));
                            break;
                        }
                    }
                }
            }
        }

        // Order matters here. Drop rules belonging to already-permissive types
        // FIRST, then measure what is left against the budget.
        //
        // Doing it the other way round lets doomed rules consume budget and
        // evict live ones: a process_creation rule set that is on its way to
        // permissive (because some later file uses `Image|contains`) still has
        // its terms pushed, and if those land past the cap they push a
        // perfectly good FILE or LSM rule out. That is a silent loss of
        // filtering for a type that had nothing wrong with it.
        kernel_rules.retain(|kr| permissive_mask & (1 << kr.event_type) == 0);

        // Whatever still overflows genuinely does not fit. Fail those types
        // open rather than truncating, which would drop events no remaining
        // rule claims.
        if kernel_rules.len() > MAX_KERNEL_RULES {
            let mut kept: Vec<KernelRule> = Vec::with_capacity(MAX_KERNEL_RULES);
            for kr in &kernel_rules {
                if kept.len() < MAX_KERNEL_RULES {
                    kept.push(*kr);
                } else {
                    if permissive_mask & (1 << kr.event_type) == 0 {
                        permissive_notes.push(format!(
                            "event type {} overflowed the {}-rule kernel budget",
                            kr.event_type, MAX_KERNEL_RULES
                        ));
                    }
                    permissive_mask |= 1 << kr.event_type;
                }
            }
            kernel_rules = kept;
            // A type that just went permissive must not keep its now-dead rules.
            kernel_rules.retain(|kr| permissive_mask & (1 << kr.event_type) == 0);
        }

        Self {
            sigma_engine,
            kernel_rules,
            permissive_mask,
            permissive_notes,
            syslog: Mutex::new(connect_syslog()),
        }
    }

    pub fn compile_kernel_rules(&self) -> Vec<KernelRule> {
        self.kernel_rules.clone()
    }

    pub fn permissive_mask(&self) -> u32 {
        self.permissive_mask
    }

    /// Print exactly which event types the kernel fast-path is filtering and
    /// which are passing everything through, so the CPU cost of a permissive
    /// type is never a surprise in production.
    pub fn report_kernel_filter(&self) {
        println!(
            "Kernel fast-path: {} rules loaded (budget {})",
            self.kernel_rules.len(),
            MAX_KERNEL_RULES
        );
        for (et, label) in [
            (ET_EXECVE, "EXECVE"),
            (ET_FILE, "FILE"),
            (ET_LSM, "LSM"),
            (ET_MODULE, "MODULE"),
            (ET_NETWORK, "NETWORK"),
        ] {
            let n = self
                .kernel_rules
                .iter()
                .filter(|r| r.event_type == et)
                .count();
            if self.permissive_mask & (1 << et) != 0 {
                println!("  {:<8} PERMISSIVE - all events forwarded to userspace", label);
            } else if n == 0 {
                println!("  {:<8} no rules - events dropped in kernel", label);
            } else {
                println!("  {:<8} filtering with {} kernel rules", label, n);
            }
        }
        for note in &self.permissive_notes {
            println!("  first blocker: {}", note);
        }
    }

    pub fn process_event(&self, ev: &Event) {
        let mut map = std::collections::HashMap::new();

        let cat = match ev.event_type.as_ref() {
            "EXECVE" => "process_creation",
            "SYSCALL" => "syscall",
            "LSM" => "lsm",
            other => other,
        };
        map.insert("category".to_string(), cat.to_string());
        map.insert("product".to_string(), "linux".to_string());

        map.insert("Image".to_string(), ev.process_name.to_string());
        map.insert("User".to_string(), ev.user_name.to_string());

        if let Some(cmd) = &ev.cmdline {
            map.insert("CommandLine".to_string(), cmd.to_string());
        }
        if let Some(path) = &ev.file_path {
            map.insert("TargetFilename".to_string(), path.to_string());
        }
        if let Some(sys) = &ev.syscall {
            map.insert("Syscall".to_string(), sys.to_string());
        }
        if let Some(net) = &ev.network {
            map.insert("DestinationIp".to_string(), net.dest_ip.to_string());
            map.insert("DestinationPort".to_string(), net.dest_port.to_string());
        }

        let matches = self.sigma_engine.evaluate_event(&map);
        if matches.is_empty() {
            return;
        }

        let event_json = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_string());

        // Take both sinks once per batch rather than per alert: `println!`
        // re-acquires the stdout lock on every call, and re-opening the syslog
        // socket per alert would put a connect() syscall back on this path.
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let mut syslog = self.syslog.lock().unwrap_or_else(|e| e.into_inner());
        if syslog.is_none() {
            *syslog = connect_syslog();
        }

        for m in matches {
            let alert = format!(
                r#"{{"id": "{}", "title": "{}", "severity": "{}", "event": {}}}"#,
                m.rule_id, m.rule_title, m.rule_level, event_json
            );

            let _ = writeln!(out, "{}", alert);

            if let Some(writer) = syslog.as_mut() {
                let sent = match m.rule_level.as_str() {
                    "critical" | "high" => writer.err(&alert),
                    "medium" => writer.warning(&alert),
                    _ => writer.info(&alert),
                };
                if sent.is_err() {
                    // Socket died (syslogd restarted, journal rotated). Drop it
                    // so the next alert reconnects instead of failing forever.
                    *syslog = None;
                }
            }
        }
    }
}

fn connect_syslog() -> Option<SyslogWriter> {
    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_USER,
        hostname: None,
        process: "openxdr-agent".into(),
        pid: std::process::id(),
    };
    match syslog::unix(formatter) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("syslog unavailable, alerts go to stdout only: {}", e);
            None
        }
    }
}

fn classify_event_type(yaml: &serde_yaml::Value) -> u8 {
    let mut event_type = match yaml
        .get("logsource")
        .and_then(|l| l.get("category"))
        .and_then(|c| c.as_str())
    {
        Some("process_creation") => ET_EXECVE,
        Some("syscall") => ET_FILE,
        Some("lsm") => ET_LSM,
        Some("network") | Some("network_connection") => ET_NETWORK,
        _ => 0,
    };

    // Module load rules are syscall-sourced but land on a different probe.
    if let Some(detection) = yaml.get("detection").and_then(|d| d.as_mapping()) {
        for (sel_key, sel_val) in detection {
            if !sel_key.as_str().unwrap_or("").starts_with("selection") {
                continue;
            }
            let Some(map) = sel_val.as_mapping() else {
                continue;
            };
            for (k, v) in map {
                if k.as_str().map(|s| s.split('|').next().unwrap_or(s)) != Some("Syscall") {
                    continue;
                }
                let mut sys = Vec::new();
                collect_scalars(v, &mut sys);
                if sys.iter().any(|s| s == "init_module" || s == "finit_module") {
                    event_type = ET_MODULE;
                }
            }
        }
    }

    event_type
}

/// Lower a rule's selection blocks into kernel byte patterns.
///
/// Correctness rule: the kernel filter must accept a **superset** of what Sigma
/// accepts. So we take the union of one field's values across every selection
/// branch, and bail out to permissive the moment any branch could match an
/// event this union would reject.
fn extract_pushdown(yaml: &serde_yaml::Value, event_type: u8) -> Pushdown {
    // `Image` is the executable path at process creation, so it belongs on the
    // path buffer (execve's `filename`), not on `comm` -- at sys_enter_execve
    // `comm` is still the *calling* process. At bprm_check the task is the
    // actor, so there `Image` really is `comm`.
    let (field, slot) = match event_type {
        ET_EXECVE => ("Image", Slot::Path),
        ET_FILE => ("TargetFilename", Slot::Path),
        ET_LSM => ("Image", Slot::Comm),
        _ => {
            return Pushdown {
                terms: Vec::new(),
                slot: Slot::Path,
                permissive_reason: Some("event type has no pushable field".into()),
            }
        }
    };

    let mut terms = Vec::new();
    let mut saw_selection = false;

    let Some(detection) = yaml.get("detection").and_then(|d| d.as_mapping()) else {
        return Pushdown {
            terms,
            slot,
            permissive_reason: Some("no detection block".into()),
        };
    };

    for (sel_key, sel_val) in detection {
        let sel_name = sel_key.as_str().unwrap_or("");
        // `filter*` blocks only ever subtract from a selection, so ignoring
        // them keeps us a superset. Anything else is not a selection branch.
        if !sel_name.starts_with("selection") {
            continue;
        }
        saw_selection = true;

        let Some(map) = sel_val.as_mapping() else {
            return Pushdown {
                terms,
                slot,
                permissive_reason: Some(format!("{} is not a field mapping", sel_name)),
            };
        };

        let mut branch_terms = Vec::new();
        for (k, v) in map {
            let Some(k_str) = k.as_str() else { continue };
            let mut parts = k_str.split('|');
            if parts.next().unwrap_or(k_str) != field {
                continue;
            }

            let kind = match modifier_kind(parts.collect::<Vec<_>>()) {
                Some(kind) => kind,
                None => {
                    return Pushdown {
                        terms,
                        slot,
                        permissive_reason: Some(format!("unsupported modifier in `{}`", k_str)),
                    }
                }
            };

            let mut values = Vec::new();
            collect_scalars(v, &mut values);
            for value in values {
                match anchor(&value, kind) {
                    Some(term) => branch_terms.push(term),
                    None => {
                        return Pushdown {
                            terms,
                            slot,
                            permissive_reason: Some(format!("unsupported wildcard in {:?}", value)),
                        }
                    }
                }
            }
        }

        // A branch with no constraint on our field can match anything, so the
        // union of the other branches is no longer a superset.
        if branch_terms.is_empty() {
            return Pushdown {
                terms,
                slot,
                permissive_reason: Some(format!("`{}` has no {} constraint", sel_name, field)),
            };
        }
        terms.extend(branch_terms);
    }

    if !saw_selection || terms.is_empty() {
        return Pushdown {
            terms,
            slot,
            permissive_reason: Some("no usable selection".into()),
        };
    }

    Pushdown {
        terms,
        slot,
        permissive_reason: None,
    }
}

/// Map Sigma field modifiers onto a kernel match kind.
///
/// `all` only changes whether the value list is AND-ed or OR-ed. We emit one
/// kernel rule per value either way, which is a superset of the AND case.
fn modifier_kind(mods: Vec<&str>) -> Option<u8> {
    let mut kind = MATCH_EXACT;
    for m in mods {
        match m {
            "startswith" => kind = MATCH_PREFIX,
            "endswith" => kind = MATCH_SUFFIX,
            "all" => {}
            // `contains`, `re`, `base64*`, `cidr`, ... cannot be lowered.
            _ => return None,
        }
    }
    Some(kind)
}

/// Fold literal wildcards in a value into the match kind, or reject it.
fn anchor(value: &str, kind: u8) -> Option<Term> {
    let stars = value.matches('*').count();
    if value.contains('?') {
        return None;
    }

    let (trimmed, kind) = match stars {
        0 => (value, kind),
        1 if value.starts_with('*') && kind == MATCH_EXACT => (&value[1..], MATCH_SUFFIX),
        1 if value.ends_with('*') && kind == MATCH_EXACT => {
            (&value[..value.len() - 1], MATCH_PREFIX)
        }
        // `*x*` is a contains, interior stars are arbitrary globs: neither is
        // representable within the per-syscall CPU budget.
        _ => return None,
    };

    if trimmed.is_empty() {
        return None;
    }
    Some(Term {
        value: trimmed.to_string(),
        kind,
    })
}

fn lower_term(event_type: u8, slot: Slot, term: &Term) -> Option<KernelRule> {
    let bytes = term.value.as_bytes();
    let mut kr = KernelRule {
        event_type,
        check_comm: 0,
        comm_kind: MATCH_EXACT,
        comm_len: 0,
        check_path: 0,
        path_kind: MATCH_EXACT,
        path_len: 0,
        _pad: 0,
        comm: [0; 16],
        path: [0; MAX_PATTERN_LEN],
    };

    // Truncating a pattern would widen it for prefix and *change* it for
    // suffix, so an oversized pattern is a hard failure, not a silent trim.
    match slot {
        Slot::Comm => {
            if bytes.len() > 16 {
                return None;
            }
            kr.check_comm = 1;
            kr.comm_kind = term.kind;
            kr.comm_len = bytes.len() as u8;
            kr.comm[..bytes.len()].copy_from_slice(bytes);
        }
        Slot::Path => {
            if bytes.len() > MAX_PATTERN_LEN {
                return None;
            }
            kr.check_path = 1;
            kr.path_kind = term.kind;
            kr.path_len = bytes.len() as u8;
            kr.path[..bytes.len()].copy_from_slice(bytes);
        }
    }
    Some(kr)
}

fn collect_scalars(v: &serde_yaml::Value, out: &mut Vec<String>) {
    if let Some(s) = v.as_str() {
        out.push(s.to_string());
    } else if let Some(seq) = v.as_sequence() {
        for item in seq {
            if let Some(s) = item.as_str() {
                out.push(s.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openxdr_common::pattern_matches;

    fn yaml(s: &str) -> serde_yaml::Value {
        serde_yaml::from_str(s).unwrap()
    }

    #[test]
    fn endswith_lowers_to_an_anchored_suffix() {
        let r = yaml(
            "logsource: {category: process_creation, product: linux}\n\
             detection:\n  selection:\n    Image|endswith: '/curl'\n  condition: selection\n",
        );
        let p = extract_pushdown(&r, ET_EXECVE);
        assert!(p.permissive_reason.is_none());
        assert_eq!(p.terms.len(), 1);
        assert_eq!(p.terms[0].value, "/curl");
        assert_eq!(p.terms[0].kind, MATCH_SUFFIX);
    }

    #[test]
    fn contains_forces_the_event_type_permissive() {
        // Silently degrading `contains` to a prefix is what produced kernel
        // filtering that disagreed with the Sigma engine.
        let r = yaml(
            "logsource: {category: process_creation, product: linux}\n\
             detection:\n  selection:\n    Image|contains: 'nmap'\n  condition: selection\n",
        );
        assert!(extract_pushdown(&r, ET_EXECVE).permissive_reason.is_some());
    }

    #[test]
    fn a_selection_branch_without_the_field_forces_permissive() {
        // `selection1 or selection2`: filtering on selection1's Image alone
        // would drop events that only selection2 can match.
        let r = yaml(
            "logsource: {category: process_creation, product: linux}\n\
             detection:\n  selection1:\n    Image|endswith: '/nc'\n\
             \x20 selection2:\n    CommandLine|contains: '-e /bin/sh'\n\
             \x20 condition: selection1 or selection2\n",
        );
        assert!(extract_pushdown(&r, ET_EXECVE).permissive_reason.is_some());
    }

    #[test]
    fn filter_blocks_are_ignored_because_they_only_subtract() {
        let r = yaml(
            "logsource: {category: lsm, product: linux}\n\
             detection:\n  selection:\n    Image: ['sudo', 'su']\n\
             \x20 filter:\n    TargetFilename: '/usr/bin/unix_chkpwd'\n\
             \x20 condition: selection and not filter\n",
        );
        let p = extract_pushdown(&r, ET_LSM);
        assert!(p.permissive_reason.is_none());
        assert_eq!(p.terms.len(), 2);
        assert_eq!(p.slot, Slot::Comm);
    }

    #[test]
    fn leading_wildcard_becomes_a_suffix_not_a_bare_substring() {
        let t = anchor("*/bin/sh", MATCH_EXACT).unwrap();
        assert_eq!(t.value, "/bin/sh");
        assert_eq!(t.kind, MATCH_SUFFIX);
        // ...and a double wildcard is a `contains`, which we refuse.
        assert!(anchor("*sh*", MATCH_EXACT).is_none());
        assert!(anchor("a?c", MATCH_EXACT).is_none());
    }

    #[test]
    fn oversized_patterns_are_rejected_never_truncated() {
        // Truncating a suffix changes which paths it matches.
        let long = "/".repeat(65);
        assert!(lower_term(
            ET_EXECVE,
            Slot::Path,
            &Term { value: long, kind: MATCH_SUFFIX }
        )
        .is_none());
        assert!(lower_term(
            ET_LSM,
            Slot::Comm,
            &Term { value: "a-very-long-process-name".into(), kind: MATCH_EXACT }
        )
        .is_none());
    }

    #[test]
    fn the_kernel_filter_accepts_a_superset_of_the_sigma_rule() {
        // End-to-end on the real corpus: every lowered rule must actually
        // match the path its Sigma source was written for.
        let engine = Engine::new("src/lib/sigma-rules");
        assert!(
            !engine.compile_kernel_rules().is_empty(),
            "no rules lowered at all - the fast-path would be dead weight"
        );
        for kr in engine.compile_kernel_rules() {
            assert!(kr.check_comm == 1 || kr.check_path == 1, "wildcard rule leaked into the kernel set");
            if kr.check_path == 1 {
                let n = kr.path_len as usize;
                let mut buf = [0u8; 512];
                // Build a path that the pattern must match by construction.
                let s: &[u8] = &kr.path[..n];
                match kr.path_kind {
                    MATCH_SUFFIX => buf[..n].copy_from_slice(s),
                    _ => buf[..n].copy_from_slice(s),
                }
                assert!(
                    pattern_matches(&buf, n, &kr.path, n, kr.path_kind),
                    "lowered rule cannot match its own pattern: {:?}",
                    String::from_utf8_lossy(s)
                );
            }
        }
    }

    #[test]
    fn a_doomed_types_rules_cannot_evict_a_healthy_types_rules() {
        // Regression: the budget check used to run BEFORE dead rules were
        // dropped. process_creation terms are pushed as files are read, and
        // only later does an `Image|contains` rule turn that whole type
        // permissive -- so its doomed rules sat in the list consuming budget.
        // With MAX_KERNEL_RULES at 32 they overflowed the cap and evicted
        // FILE's rules, silently disabling a fast path that was perfectly
        // healthy. Symptom was "event type 2 overflowed the budget" with only
        // 11 rules actually loaded.
        let engine = Engine::new("src/lib/sigma-rules");
        let rules = engine.compile_kernel_rules();
        let mask = engine.permissive_mask();

        let file_rules = rules.iter().filter(|r| r.event_type == ET_FILE).count();
        assert!(
            mask & (1 << ET_FILE) == 0,
            "FILE went permissive; another type's discarded rules likely ate the budget"
        );
        assert!(file_rules > 0, "FILE should retain its TargetFilename rules");
        assert!(rules.len() <= MAX_KERNEL_RULES);
    }

    #[test]
    fn permissive_types_carry_no_dead_kernel_rules() {
        let engine = Engine::new("src/lib/sigma-rules");
        let mask = engine.permissive_mask();
        for kr in engine.compile_kernel_rules() {
            assert_eq!(
                mask & (1 << kr.event_type),
                0,
                "event type {} is permissive but still has kernel rules",
                kr.event_type
            );
        }
        assert!(engine.compile_kernel_rules().len() <= MAX_KERNEL_RULES);
    }
}




