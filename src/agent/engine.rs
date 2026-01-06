/**
 * Engine to listen on AuditD and raise alarms if any rule is trigerred
 */
use crate::agent::{rule::Rule, Error};
use regex::Regex;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::process::Command;

/**
 * Event structure representing an audit event.
 * event_type - Type of the event (e.g., "EXECVE")
 * process_name - Name of the process (e.g., "sudo")
 * uid - User ID
 * user_name - User name (e.g., "root", "alice")
 * pid - Process ID
 * cmdline - Command line arguments
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_type: String,   // e.g. "EXECVE"
    pub process_name: String, // "sudo"
    pub uid: u32,
    pub user_name: String, // "root", "alice" (or "uid:1000" if you want)
    pub pid: u32,
    pub cmdline: String,           // optional, can be empty
    pub syscall: Option<String>,   // e.g., "open", "write"
    pub file_path: Option<String>, // e.g., "/etc/passwd"
}

/**
 * Engine structure that holds the rules and processes events.
 * rules - Vector of rules to apply
 */

#[derive(Debug)]
pub struct Engine {
    rules: Vec<Rule>,
}
/**
 * Implementation of the Engine.
 */
impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Engine { rules }
    }

    pub fn process_event(&self, ev: &Event) {
        for rule in &self.rules {
            // quick OS filter
            if rule.os != "linux" {
                continue;
            }

            if !rule_matches(rule, ev) {
                continue;
            }

            self.execute_actions(rule, ev);
        }
    }

    fn execute_actions(&self, rule: &Rule, ev: &Event) {
        for action in &rule.actions {
            match action.action_type.as_str() {
                "alert_json" => emit_alert_json(rule, ev, &action.destination),
                _ => {
                    // ignore unknown action types for now
                }
            }
        }
    }
}
/**
 * Check if a rule matches an event
 * rule - The rule to check
 * ev - The event to check against
 * Returns: true if the rule matches the event, false otherwise
 */
fn rule_matches(rule: &Rule, ev: &Event) -> bool {
    let m = &rule.matcher;

    if let Some(ref t) = m.event_type {
        if t != &ev.event_type {
            return false;
        }
    }

    if let Some(ref name) = m.process_name {
        if name != &ev.process_name {
            return false;
        }
    }

    if let Some(ref names) = m.process_name_in {
        if !names.contains(&ev.process_name) {
            return false;
        }
    }

    if let Some(ref list) = m.user_not_in {
        // if the current user is in the forbidden list, rule does NOT match
        if list.iter().any(|u: &String| u == &ev.user_name) {
            return false;
        }
    }

    // FIM Checks
    if let Some(ev_syscall) = &ev.syscall {
        // Check syscall match
        let mut syscall_matched = true;
        if let Some(ref syscalls) = m.syscall {
            if !syscalls.contains(ev_syscall) {
                syscall_matched = false;
            }
        }
        // Check syscall alias
        if !syscall_matched {
            if let Some(ref syscalls) = m.syscall_alias {
                if syscalls.contains(ev_syscall) {
                    syscall_matched = true;
                }
            }
        }

        // If matcher specified syscalls but none matched
        if (m.syscall.is_some() || m.syscall_alias.is_some()) && !syscall_matched {
            return false;
        }
    } else {
        // If event has no syscall, but rule requires it?
        if m.syscall.is_some() || m.syscall_alias.is_some() {
            return false;
        }
    }

    if let Some(ev_path) = &ev.file_path {
        if let Some(ref paths) = m.file_path_in {
            // simplified exact match for now
            if !paths.contains(ev_path) {
                return false;
            }
        }

        if let Some(ref regex_str) = m.file_path_regex {
            if let Ok(re) = regex::Regex::new(regex_str) {
                if !re.is_match(ev_path) {
                    return false;
                }
            } else {
                // Invalid regex in rule, fail safe or ignore?
                // Fail safe: doesn't match
                return false;
            }
        }
    } else {
        if m.file_path_in.is_some() || m.file_path_regex.is_some() {
            return false;
        }
    }

    // Process path prefix
    if let Some(ref prefixes) = m.process_path_prefix_in {
        // We only have process_name (comm) or cmdline (args).
        // Wait, existing event has `cmdline`. Using cmdline as full path?
        // ExecveEvent has `filename` which corresponds to the executed binary path.
        // engine::Event has `cmdline` mapped to `filename`.
        // So checking ev.cmdline starts_with prefix.
        if !prefixes.iter().any(|p| ev.cmdline.starts_with(p)) {
            return false;
        }
    }

    // Args regex
    if let Some(ref regex_str) = m.args_regex {
        // Check against cmdline (which might be just filename or full args depending on eBPF)
        // Currently eBPF ExecveEvent captures `filename` (path) but not full args (argv).
        // The rule `netcat_or_reverse_shell` expects arguments regex.
        // My plan says "TODO: get full args" in main.rs line 76.
        // So this check might fail or check only filename for now.
        if let Ok(re) = regex::Regex::new(regex_str) {
            if !re.is_match(&ev.cmdline) {
                // This is weak but better than nothing
                return false;
            }
        }
    }

    true
}
/**
 * Alert structure for JSON output
 * id - Rule ID
 * description - Rule description
 * severity - Rule severity
 * event - The event that triggered the alert
 */
#[derive(Debug, Serialize)]
struct Alert<'a> {
    id: &'a str,
    description: &'a str,
    severity: &'a str,
    event: &'a Event,
}

/**
 * Emit alert in JSON format to the specified destination
 * rule - The rule that triggered the alert
 * ev - The event that triggered the alert
 * destination - Where to send the alert (e.g., "stdout", "stderr", "file:/path", "tcp:host:port")
 */
fn emit_alert_json(rule: &Rule, ev: &Event, destination: &str) {
    let alert = Alert {
        id: &rule.id,
        description: &rule.description,
        severity: &rule.severity,
        event: ev,
    };

    let json = serde_json::to_string(&alert).unwrap_or_else(|_| "{}".to_string());

    match destination {
        "stdout" => {
            println!("{json}");
        }
        // you can add "stderr", "file:/path", "tcp:host:port", etc. later
        _ => {
            // ignore for now
        }
    }
}
/**
 * Open AuditD socket to listen for events
 * Returns an Error if the operation fails or if the platform is unsupported.
 */
pub fn open_auditd_socket() -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        let status = Command::new("auditctl").arg("-s").status()?;
        if status.success() {
            println!("Successfully opened auditd socket.");
            Ok(())
        } else {
            Err(Error::Other("Failed to open auditd socket".to_string()))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

/**
 * Listen for AuditD events
 * Returns an Error if the operation fails or if the platform is unsupported.
 */
pub fn listen_auditd_events() -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        // Placeholder for listening to auditd events
        println!("Listening to auditd events...");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

/**
 * Match AuditD events to rules
 * Returns a vector of matched rule IDs or an Error if the operation fails or if the platform is unsupported.
 * event - The audit event as a string
 * Returns: Vec of matched rule IDs
 */
pub fn match_event_to_rules(event: &str) -> Result<Vec<String>, Error> {
    #[cfg(target_os = "linux")]
    {
        // Placeholder for matching events to rules
        println!("Matching event to rules: {}", event);
        Ok(vec![])
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
/**
 * Raise alerts based on matched rules
 * matched_rules - Vector of matched rule IDs
 */
pub fn raise_alert(matched_rules: Vec<String>) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        // Placeholder for raising alerts
        for rule in matched_rules {
            println!("Raising alert for rule: {}", rule);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

/**
 * Set up eBPF file monitoring hooks
 * Returns an Error if the operation fails or if the platform is unsupported.
 */
pub fn setup_ebpf_file_monitoring() -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        // Placeholder for setting up eBPF hooks
        println!("Setting up eBPF file monitoring hooks...");
        // listen for file events and raise alerts

        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
