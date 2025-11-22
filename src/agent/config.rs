use std::path::PathBuf;
use std::process::Command;

use crate::agent::Error;
/**
 * Configuration for the Agent.
 */
pub struct Config {
    pub rules_path: PathBuf,
    pub os_type: Option<String>,
    pub arch_type: Option<String>,
    pub agent_version: Option<String>,
    pub os_distribution: Option<String>,
    pub os_kernel_version: Option<String>,
    pub os_release: Option<String>,
}


impl Config {

    pub fn load_default() -> Result<Self, Error> {
        let rules_path = PathBuf::from("src/lib/alert-rules.yaml");

        // Basic compile-time data
        let os_type = Some(std::env::consts::OS.to_string());
        let arch_type = Some(std::env::consts::ARCH.to_string());
        let agent_version = Some(env!("CARGO_PKG_VERSION").to_string());

        // Best-effort runtime detection; failures are non-fatal and leave fields as None.
        let os_distribution = detect_os_distribution();
        let os_kernel_version = detect_os_kernel_version();
        let os_release = detect_os_release();

        Ok(Self {
            rules_path,
            os_type,
            arch_type,
            agent_version,
            os_distribution,
            os_kernel_version,
            os_release,
        })
    }


    // Getter methods returning owned Strings for convenient logging/printing.
    pub fn os_type_string(&self) -> String {
        self.os_type
            .clone()
            .unwrap_or_else(|| "unknown-os-type".to_string())
    }

    pub fn arch_type_string(&self) -> String {
        self.arch_type
            .clone()
            .unwrap_or_else(|| "unknown-arch".to_string())
    }

    pub fn agent_version_string(&self) -> String {
        self.agent_version
            .clone()
            .unwrap_or_else(|| "unknown-agent-version".to_string())
    }

    pub fn os_distribution_string(&self) -> String {
        self.os_distribution
            .clone()
            .unwrap_or_else(|| "unknown-distribution".to_string())
    }

    pub fn os_kernel_version_string(&self) -> String {
        self.os_kernel_version
            .clone()
            .unwrap_or_else(|| "unknown-kernel-version".to_string())
    }

    pub fn os_release_string(&self) -> String {
        self.os_release
            .clone()
            .unwrap_or_else(|| "unknown-release".to_string())
    }
}


fn detect_os_distribution() -> Option<String> {
    // Linux: prefer /etc/os-release PRETTY_NAME or NAME
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
            let mut name: Option<String> = None;
            let mut pretty: Option<String> = None;
            for line in contents.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let trimmed = value.trim().trim_matches('"');
                    match key {
                        "PRETTY_NAME" => pretty = Some(trimmed.to_string()),
                        "NAME" => name = Some(trimmed.to_string()),
                        _ => {}
                    }
                }
            }
            return pretty.or(name);
        }
    }

    #[cfg(target_os = "macos")]
    {
        return Some("macOS".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        return Some("Windows".to_string());
    }

    None
}

fn detect_os_kernel_version() -> Option<String> {
    // On Unix-like systems, try `uname -r`
    #[cfg(unix)]
    {
        if let Ok(output) = Command::new("uname").arg("-r").output() {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }

    None

}


fn detect_os_release() -> Option<String> {
    // On Unix-like systems, try `uname -v`
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("uname").arg("-v").output() {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("ver").output() {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some("MacOS".to_string()+" "+ &s);
                }
            }
        }
    }

    None
}

