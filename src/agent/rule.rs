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
}

#[derive(Debug, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: String, // "alert_json", etc.
    pub destination: String, // "stdout", "file", ...
}

pub fn load_rules<P: AsRef<Path>>(path: P) -> Result<RuleSet, Error> {
    #[cfg(target_os = "linux")] {
        let contents = fs::read_to_string(path)?;
        let rules = contents.split('\n').filter(|line| !line.trim().is_empty()).collect::<Vec<&str>>().join("\n");
        let rules: RuleSet = serde_yaml::from_str(&rules)?;
        println!("Loaded {} rules ", rules.rules.len());
        for rule in &rules.rules {
            println!("  - Rule ID: {}, Description: {:?}", rule.id, rule.description);
        }
        Ok(rules)

    }
    #[cfg(not(target_os = "linux"))] {
        Err(Error::UnsupportedPlatform)
    }

}


pub fn load_default_rules_auditd() -> Result<RuleSet, Error> {
    //load default rules from src/lib/alert-rules.yaml
    #[cfg(target_os = "linux")] {

        let contents = fs::read_to_string("src/lib/alert-rules.yaml")?;
        let rules = serde_yaml::from_str(&contents)?;
        Ok(rules)
        }
    #[cfg(not(target_os = "linux"))] {
        Err(Error::UnsupportedPlatform)
    }

}


pub fn add_rules_to_auditd(rules: String) -> Result<(), Error> {
    //Assume rules read from file are in correct format (file auditd-rules.raw)
     #[cfg(target_os = "linux")]  {
        println!("Adding rules to auditd: \n");
        let rule_lines: Vec<&str> = rules.lines().collect();
        
        let cleansed_trailing_newline_rules: Vec<&str> = rule_lines.into_iter().filter(|line| !line.trim().is_empty()).collect();
        for line in &cleansed_trailing_newline_rules {
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
    // TODO implement windows and macos support
    #[cfg(not(target_os = "linux"))] {
        Err(Error::UnsupportedPlatform)
    }
}

pub fn remove_rules_from_auditd(rules: &RuleSet) -> Result<(), Error> {
    for rule in &rules.rules {
        let rule_str = format!(
            "-a always,exit -F key={} -S all",
            rule.id
        );
        Command::new("auditctl")
            .arg("-W")
            .arg(&rule_str)
            .output()?;
    }
    Ok(())
}
pub fn clear_all_auditd_rules() -> Result<(), Error> {
    Command::new("auditctl")
        .arg("-D")
        .output()?;
    Ok(())
}

pub fn list_auditd_rules() -> Result<String, Error> {
    let output = Command::new("auditctl")
        .arg("-l")
        .output()?;
    let rules = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(rules)
}



