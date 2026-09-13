use std::fmt::Write;
use std::path::PathBuf;
use std::process::Command;
use pnet::datalink;
use crate::agent::Error;

/**
 * Configuration for the Agent.
 * rules_path - Path to the rules file
 * os_type - Operating system type (e.g., "linux", "windows")
 * arch_type - Architecture type (e.g., "x86_64", "arm64
 * agent_version - Version of the agent
 * os_distribution - OS distribution (e.g., "Ubuntu", "Windows 10")
 * os_kernel_version - Kernel version of the OS
 * os_release - OS release information
 * network_config - Network configuration details
 * enableLocalUI - Flag to enable local UI (default: false)
 */
pub struct Config {
    pub rules_path: PathBuf,
    pub os_type: Option<String>,
    pub arch_type: Option<String>,
    pub agent_version: Option<String>,
    pub os_distribution: Option<String>,
    pub os_kernel_version: Option<String>,
    pub os_release: Option<String>,
    pub network_config: Option<NetworkConfig>,
    pub enableLocalUI : bool //Default: false
}

/**
 * Information about a network interface.
 * name - Name of the interface
 * mac_address - MAC address of the interface
 * ips - List of IP addresses assigned to the interface
 */
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac_address: Option<String>,
    pub ips: Vec<String>
}
/**
 * Network configuration details.
 * interfaces - List of network interfaces
 * dns_servers - List of DNS servers
 * gateway - Default gateway
 */
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub interfaces: Vec<InterfaceInfo>,
    pub dns_servers: Vec<String>,
    pub gateway: Option<String>,
}

/**
 * Implementation of the Config.
 */
impl Config {


    pub fn new(   rules_path: PathBuf,
     os_type: Option<String>,
    arch_type: Option<String>,
    agent_version: Option<String>,
    os_distribution: Option<String>,
    os_kernel_version: Option<String>,
    os_release: Option<String>,
    network_config: Option<NetworkConfig>,
    enable_local_ui : bool ) -> Self {
        Self {
            rules_path,
            os_type,
            arch_type,
            agent_version,
            os_distribution,
            os_kernel_version,
            os_release,
            network_config,
            enableLocalUI: enable_local_ui
        }
    }
/**
 * Load the default configuration for the agent.
 * Returns: Config instance or Error if loading fails
 */
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
        let network_config = Some(NetworkConfig::new(
            NetworkConfig::fetch_interfaces_from_runtime(),
            NetworkConfig::fetch_dns_servers_from_runtime(),
            None, // Gateway detection can be added later
        ));
        let enableLocalUI = false;
        Ok(Self {
            rules_path,
            os_type,
            arch_type,
            agent_version,
            os_distribution,
            os_kernel_version,
            os_release,
            network_config,
            enableLocalUI
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
/**
 * Convert the global configuration to a formatted string.
 * config - Reference to the Config instance
 * Returns: Formatted string representation of the configuration
 */
pub fn global_to_string(config: &Config) -> String {
    const LABEL_WIDTH: usize = 20;
    let divider = "==============================";
    let mut output = String::new();

    let _ = writeln!(output, "{divider}");
    let _ = writeln!(output, "Agent Configuration");
    let _ = writeln!(output, "{divider}");
    write_field(&mut output, LABEL_WIDTH, "OS Type", config.os_type_string());
    write_field(
        &mut output,
        LABEL_WIDTH,
        "Architecture Type",
        config.arch_type_string(),
    );
    write_field(
        &mut output,
        LABEL_WIDTH,
        "Agent Version",
        config.agent_version_string(),
    );
    write_field(
        &mut output,
        LABEL_WIDTH,
        "OS Distribution",
        config.os_distribution_string(),
    );
    write_field(
        &mut output,
        LABEL_WIDTH,
        "OS Kernel Version",
        config.os_kernel_version_string(),
    );
    write_field(
        &mut output,
        LABEL_WIDTH,
        "OS Release",
        config.os_release_string(),
    );
    write_field(
        &mut output,
        LABEL_WIDTH,
        "Enable Local UI",
        if config.enableLocalUI { "Yes" } else { "No" },
    );

    output.push('\n');
    match &config.network_config {
        Some(network) => output.push_str(&format_network_config(network, LABEL_WIDTH)),
        None => write_field(&mut output, LABEL_WIDTH, "Network", "None"),
    }

    output
}
/**
 * Helper function to write a labeled field to the output string.
 * output - Mutable reference to the output string
 * label_width - Width for label alignment
 * label - Label for the field
 * value - Value of the field
 * Returns: ()
 */
fn write_field(output: &mut String, label_width: usize, label: &str, value: impl AsRef<str>) {
    let _ = writeln!(
        output,
        "{label:<width$}: {}",
        value.as_ref(),
        width = label_width
    );
}
/**
 * Format the network configuration into a string.
 * network - Reference to the NetworkConfig instance
 * label_width - Width for label alignment
 * Returns: Formatted string representation of the network configuration
 */
fn format_network_config(network: &NetworkConfig, label_width: usize) -> String {
    let mut output = String::new();
    write_field(&mut output, label_width, "Network", " ");

    if network.interfaces.is_empty() {
        let _ = writeln!(output, "  Interfaces: none detected");
    } else {
        let _ = writeln!(output, "  Interfaces:");
        for iface in &network.interfaces {
            let mac = iface
                .mac_address
                .clone()
                .unwrap_or_else(|| "no-mac-address".to_string());
            let ips = if iface.ips.is_empty() {
                "no IPs".to_string()
            } else {
                iface.ips.join(", ")
            };
            let _ = writeln!(output, "    - {} (MAC: {})", iface.name, mac);
            let _ = writeln!(output, "      IPs: {}", ips);
        }
    }

    let dns = if network.dns_servers.is_empty() {
        "none".to_string()
    } else {
        network.dns_servers.join(", ")
    };
    let gateway = network
        .gateway
        .clone()
        .unwrap_or_else(|| "None".to_string());
    let _ = writeln!(output, "  DNS Servers: {}", dns);
    let _ = writeln!(output, "  Gateway: {}", gateway);

    output
}

/**
 * Detect the operating system distribution.
 * Returns: Option containing the OS distribution string if detected
 */
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
/**
 * Detect the operating system kernel version.
 * Returns: Option containing the OS kernel version string if detected
 */
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

/**
 * Detect the operating system release information.
 * Returns: Option containing the OS release string if detected
 */
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

/**
 * Implementation of the InterfaceInfo.
 */
impl InterfaceInfo {
    pub fn new(name: String, mac_address: Option<String>, ips: Vec<String>) -> Self {
        Self {
            name,
            mac_address,
            ips,
        }
    }
}
/**
 * Implementation of the NetworkConfig.
 */
impl NetworkConfig {
    pub fn new(interfaces: Vec<InterfaceInfo>, dns_servers: Vec<String>, gateway: Option<String>) -> Self {
        Self {
            interfaces,
            dns_servers,
            gateway,
        }
    }
    /**
     * Fetch network interfaces from the runtime environment.
     * Returns: Vector of InterfaceInfo instances
     */
    pub fn fetch_interfaces_from_runtime() -> Vec<InterfaceInfo> {
        let mut interface_infos = Vec::new();
        let interfaces = datalink::interfaces();

        for interface in interfaces {
            let name = interface.name.clone();
            let mac_address = interface.mac.map(|mac| mac.to_string());
            let ips: Vec<String> = interface.ips.iter().map(|ip| ip.ip().to_string()).collect();

            let interface_info = InterfaceInfo::new(name, mac_address, ips);
            interface_infos.push(interface_info);
        }

        interface_infos
    }
    /**
     * Fetch DNS servers from the runtime environment.
     * Returns: Vector of DNS server addresses as strings
     */
    pub fn fetch_dns_servers_from_runtime() -> Vec<String> {
        let mut dns_servers = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
                for line in contents.lines() {
                    if line.starts_with("nameserver") {
                        if let Some(server) = line.split_whitespace().nth(1) {
                            dns_servers.push(server.to_string());
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
                for line in contents.lines() {
                    if line.starts_with("nameserver") {
                        if let Some(server) = line.split_whitespace().nth(1) {
                            dns_servers.push(server.to_string());
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("nslookup").arg("-type=ns").arg("localhost").output() {
                if output.status.success() {
                    let s = String::from_utf8_lossy(&output.stdout);
                    for line in s.lines() {
                        if line.contains("Address:") {
                            if let Some(addr) = line.split_whitespace().nth(1) {
                                dns_servers.push(addr.to_string());
                            }
                        }
                    }
                }
            }
        }

        dns_servers
    }
}
