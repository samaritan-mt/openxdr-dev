
/**
 * Engine to listen on AuditD and raise alarms if any rule is trigerred
 */

use crate::agent::{Error, rule::Rule};
#[cfg(target_os = "linux")]
use std::process::Command;
use serde::Serialize;
use serde::Deserialize;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_type: String,    // e.g. "EXECVE"
    pub process_name: String,  // "sudo"
    pub uid: u32,
    pub user_name: String,     // "root", "alice" (or "uid:1000" if you want)
    pub pid: u32,
    pub cmdline: String,       // optional, can be empty
}

#[derive(Debug)]
pub struct Engine {
    rules: Vec<Rule>,
}

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

    if let Some(ref list) = m.user_not_in {
        // if the current user is in the forbidden list, rule does NOT match
        if list.iter().any(|u: &String| u == &ev.user_name) {
            return false;
        }
    }

    true
}

#[derive(Debug, Serialize)]
struct Alert<'a> {
    id: &'a str,
    description: &'a str,
    severity: &'a str,
    event: &'a Event,
}

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

pub fn open_auditd_socket() -> Result<(), Error> {
    #[cfg(target_os = "linux")] {
        let status = Command::new("auditctl")
            .arg("-s")
            .status()?;
        if status.success() {
            println!("Successfully opened auditd socket.");
            Ok(())
        } else {
            Err(Error::Other("Failed to open auditd socket".to_string()))
        }
    }
    #[cfg(not(target_os = "linux"))] {
        Err(Error::UnsupportedPlatform)
    }
}


pub fn listen_auditd_events() -> Result<(), Error> {
    #[cfg(target_os = "linux")] {
        // Placeholder for listening to auditd events
        println!("Listening to auditd events...");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))] {
        Err(Error::UnsupportedPlatform)
    }
}


pub fn match_event_to_rules(event: &str) -> Result<Vec<String>, Error> {
    #[cfg(target_os = "linux")] {
        // Placeholder for matching events to rules
        println!("Matching event to rules: {}", event);
        Ok(vec![])
    }
    #[cfg(not(target_os = "linux"))] {
        Err(Error::UnsupportedPlatform)
    }
}

pub fn raise_alert(matched_rules: Vec<String>) -> Result<(), Error> {
    #[cfg(target_os = "linux")] {
        // Placeholder for raising alerts
        for rule in matched_rules {
            println!("Raising alert for rule: {}", rule);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))] {
        Err(Error::UnsupportedPlatform)
    }
}
