use openxdr_common::KernelRule;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fs;
use std::path::Path;

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
    pub cmdline: Option<Cow<'a, str>>,   // optional, can be empty
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall: Option<Cow<'a, str>>,   // e.g., "open", "write"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<Cow<'a, str>>, // e.g., "/etc/passwd"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkDetails<'a>>, // Network details if applicable
}

#[derive(Deserialize, Debug)]
struct SigmaLogsource {
    category: Option<String>,
}

pub struct Engine {
    sigma_engine: null_sigma::engine::SigmaEngine,
    kernel_rules: Vec<KernelRule>,
}

impl Engine {
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Self {
        let mut sigma_engine = null_sigma::engine::SigmaEngine::new();
        let mut kernel_rules = Vec::new();

        if let Ok(entries) = fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("yml") {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        // 1. Load into Sigma Engine
                        if let Err(e) = sigma_engine.load_rule(&content) {
                            eprintln!("Failed to load rule {:?}: {:?}", entry.path(), e);
                            continue;
                        }

                        // 2. Parse manually to extract KernelRule fast-paths
                        if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                            let mut event_type = 0;
                            if let Some(logsource) = yaml.get("logsource") {
                                if let Some(cat) = logsource.get("category").and_then(|c| c.as_str()) {
                                    match cat {
                                        "process_creation" => event_type = 1,
                                        "syscall" => event_type = 2,
                                        "lsm" => event_type = 3,
                                        "network" => event_type = 4, // Might not have dedicated eBPF event_type for network yet, but let's be safe
                                        _ => {}
                                    }
                                }
                            }

                            let mut images = Vec::new();
                            let mut targets = Vec::new();

                            if let Some(detection) = yaml.get("detection").and_then(|d| d.as_mapping()) {
                                for (sel_key, sel_val) in detection {
                                    let sel_name = sel_key.as_str().unwrap_or("");
                                    if sel_name.starts_with("selection") {
                                        if let Some(map) = sel_val.as_mapping() {
                                            for (k, v) in map {
                                                if let Some(k_str) = k.as_str() {
                                                    let base_key = k_str.split('|').next().unwrap_or(k_str);
                                                    if base_key == "Image" {
                                                        extract_strings(v, &mut images);
                                                    } else if base_key == "TargetFilename" {
                                                        extract_strings(v, &mut targets);
                                                    } else if base_key == "Syscall" {
                                                        let mut sys = Vec::new();
                                                        extract_strings(v, &mut sys);
                                                        if sys.iter().any(|s| s == "init_module" || s == "finit_module") {
                                                            event_type = 4;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if images.is_empty() { images.push("".to_string()); }
                            if targets.is_empty() { targets.push("".to_string()); }

                            for img in &images {
                                for tgt in &targets {
                                    let mut kr = KernelRule {
                                        event_type,
                                        check_comm: 0,
                                        comm: [0; 16],
                                        check_path: 0,
                                        path: [0; 64],
                                    };

                                    if !img.is_empty() {
                                        kr.check_comm = 1;
                                        let bytes = img.as_bytes();
                                        let len = bytes.len().min(16);
                                        kr.comm[..len].copy_from_slice(&bytes[..len]);
                                    }

                                    if !tgt.is_empty() {
                                        kr.check_path = 1;
                                        let bytes = tgt.as_bytes();
                                        let len = bytes.len().min(64);
                                        kr.path[..len].copy_from_slice(&bytes[..len]);
                                    }

                                    kernel_rules.push(kr);
                                }
                            }
                        }
                    }
                }
            }
        }

        Self { sigma_engine, kernel_rules }
    }

    pub fn compile_kernel_rules(&self) -> Vec<KernelRule> {
        let mut capped = Vec::new();
        for (i, r) in self.kernel_rules.iter().enumerate() {
            if i >= 512 { break; }
            capped.push(*r);
        }
        capped
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
        for m in matches {
            let event_json = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_string());
            println!(
                r#"{{"id": "{}", "title": "{}", "severity": "{}", "event": {}}}"#,
                m.rule_id, m.rule_title, m.rule_level, event_json
            );
        }
    }
}

fn extract_strings(v: &serde_yaml::Value, out: &mut Vec<String>) {
    if let Some(s) = v.as_str() {
        // null-sigma rule matching checks exact strings. 
        // We will strip wildcards for our kernel fast-path
        let clean = s.replace("*", "").replace("^", "").replace("$", "");
        out.push(clean);
    } else if let Some(seq) = v.as_sequence() {
        for item in seq {
            if let Some(s) = item.as_str() {
                let clean = s.replace("*", "").replace("^", "").replace("$", "");
                out.push(clean);
            }
        }
    }
}
