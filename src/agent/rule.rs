use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::agent::{self, Error};

#[derive(Debug, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub os: String,

    #[serde(rename = "match")]
    pub matcher: Match,

    pub actions: Vec<Action>,
}

#[derive(Debug, Deserialize)]
pub struct Match {
    pub event_type: Option<String>,
    pub process_name: Option<String>,
    pub user_not_in: Option<Vec<String>>,

    // FIM fields
    pub syscall: Option<Vec<String>>,
    #[serde(alias = "syscall_in")]
    pub syscall_alias: Option<Vec<String>>,

    pub file_path_in: Option<Vec<String>>,
    pub file_path_regex: Option<String>,

    pub process_path_prefix_in: Option<Vec<String>>,
    pub process_name_in: Option<Vec<String>>,
    pub args_regex: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: String, // "alert_json", etc.
    pub destination: String, // "stdout", "file", ...
}

pub fn load_rules<P: AsRef<Path>>(path: P) -> Result<RuleSet, Error> {
    #[cfg(target_os = "linux")]
    {
        let contents = fs::read_to_string(path)?;
        // Original code had some split/filter/join logic likely for auditd raw rules but this function returns RuleSet from YAML
        // So standard serde_yaml frame_str is appropriate for alert-rules.yaml
        let rules_vec: Vec<Rule> = serde_yaml::from_str(&contents)?;
        let rules = RuleSet { rules: rules_vec };
        println!("Loaded {} rules ", rules.rules.len());
        for rule in &rules.rules {
            println!(
                "  - Rule ID: {}, Description: {:?}",
                rule.id, rule.description
            );
        }
        Ok(rules)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

pub fn load_default_rules_auditd() -> Result<RuleSet, Error> {
    #[cfg(target_os = "linux")]
    {
        let contents = fs::read_to_string("src/lib/alert-rules.yaml")?;
        let rules_vec: Vec<Rule> = serde_yaml::from_str(&contents)?;
        let rules = RuleSet { rules: rules_vec };
        Ok(rules)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

pub fn add_rules_to_auditd(rules: String) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        println!("Adding rules to auditd: \n");
        let rule_lines: Vec<&str> = rules.lines().collect();

        let cleansed_rules: Vec<&str> = rule_lines
            .into_iter()
            .filter(|line| !line.trim().is_empty())
            .collect();
        for line in &cleansed_rules {
            println!("  {}", line);
            let output = Command::new("auditctl")
                .args(line.split_whitespace())
                .output()?;
            if output.status.code() == Some(255) {
                println!("Rule already exists in auditd: {}", line);
                continue;
            } else if output.status.code() != Some(0) {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("Failed to add rule: {}. Error: {}", line, stderr);
                continue;
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

pub fn remove_rules_from_auditd(rules: &RuleSet) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        for rule in &rules.rules {
            let rule_str = format!("-a always,exit -F key={} -S all", rule.id);
            Command::new("auditctl").arg("-W").arg(&rule_str).output()?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

pub fn clear_all_auditd_rules() -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        Command::new("auditctl").arg("-D").output()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

pub fn list_auditd_rules() -> Result<String, Error> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("auditctl").arg("-l").output()?;
        let rules = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(rules)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
