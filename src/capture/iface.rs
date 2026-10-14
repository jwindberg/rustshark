#![allow(dead_code)]

use std::process::Command;

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub index: usize,
    pub name: String,
    pub description: String,
    pub is_loopback: bool,
    pub ip_addresses: Vec<String>,
}

pub fn list_interfaces() -> Vec<InterfaceInfo> {
    // 1. Try dumpcap -D or tshark -D first
    for bin in &["dumpcap", "tshark"] {
        if let Ok(output) = Command::new(bin).arg("-D").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let list = parse_shark_interfaces(&stdout);
                if !list.is_empty() {
                    return list;
                }
            }
        }
    }

    // 2. On Linux, enumerate /sys/class/net
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut list = Vec::new();
            for (i, entry) in entries.flatten().enumerate() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    let is_loopback = file_name == "lo" || file_name.starts_with("lo");
                    list.push(InterfaceInfo {
                        index: i + 1,
                        name: file_name.clone(),
                        description: if is_loopback { "Loopback".to_string() } else { "Network interface".to_string() },
                        is_loopback,
                        ip_addresses: Vec::new(),
                    });
                }
            }
            if !list.is_empty() {
                return list;
            }
        }
    }

    // 3. On macOS / BSD, check ifconfig -l
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        if let Ok(output) = Command::new("ifconfig").arg("-l").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut list = Vec::new();
                for (i, name) in stdout.split_whitespace().enumerate() {
                    let is_loopback = name.starts_with("lo");
                    list.push(InterfaceInfo {
                        index: i + 1,
                        name: name.to_string(),
                        description: if is_loopback { "Loopback".to_string() } else { "Network interface".to_string() },
                        is_loopback,
                        ip_addresses: Vec::new(),
                    });
                }
                if !list.is_empty() {
                    return list;
                }
            }
        }
    }

    // 4. On Windows, try netsh interface show interface
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("netsh").args(["interface", "show", "interface"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut list = Vec::new();
                for (i, line) in stdout.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("Enabled") || trimmed.starts_with("Connected") || trimmed.starts_with("Dedicated") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if let Some(&name) = parts.last() {
                            list.push(InterfaceInfo {
                                index: i + 1,
                                name: name.to_string(),
                                description: "Windows Network Interface".to_string(),
                                is_loopback: false,
                                ip_addresses: Vec::new(),
                            });
                        }
                    }
                }
                if !list.is_empty() {
                    return list;
                }
            }
        }
    }

    // Default fallback
    vec![
        InterfaceInfo {
            index: 1,
            name: "any".to_string(),
            description: "Pseudo-device that captures on all interfaces".to_string(),
            is_loopback: false,
            ip_addresses: Vec::new(),
        },
        InterfaceInfo {
            index: 2,
            name: "lo0".to_string(),
            description: "Loopback".to_string(),
            is_loopback: true,
            ip_addresses: vec!["127.0.0.1".to_string()],
        },
        InterfaceInfo {
            index: 3,
            name: "en0".to_string(),
            description: "Ethernet / Wi-Fi".to_string(),
            is_loopback: false,
            ip_addresses: Vec::new(),
        },
    ]
}

pub fn default_interface() -> String {
    let ifaces = list_interfaces();

    // 1. Prefer standard primary interfaces (en0 on macOS, eth0/wlan0 on Linux/Raspberry Pi, Ethernet/Wi-Fi on Windows)
    for target in &["en0", "eth0", "wlan0", "en1", "eth1", "Ethernet", "Wi-Fi"] {
        if ifaces.iter().any(|i| i.name.eq_ignore_ascii_case(target)) {
            return target.to_string();
        }
    }

    // 2. Any non-loopback interface
    for i in &ifaces {
        if !i.is_loopback && i.name != "any" && !i.name.starts_with("gif") && !i.name.starts_with("stf") {
            return i.name.clone();
        }
    }

    // 3. Fallback
    ifaces.first().map(|i| i.name.clone()).unwrap_or_else(|| "any".to_string())
}

fn parse_shark_interfaces(output: &str) -> Vec<InterfaceInfo> {
    let mut list = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Format: "1. en0 (Wi-Fi)" or "1. eth0"
        let parts: Vec<&str> = trimmed.splitn(2, ". ").collect();
        if parts.len() == 2 {
            let idx = parts[0].parse::<usize>().unwrap_or(list.len() + 1);
            let rest = parts[1];
            let (name, desc) = if let Some(open) = rest.find('(') {
                let name = rest[..open].trim();
                let desc = rest[open..].trim_matches(|c| c == '(' || c == ')').trim();
                (name, desc)
            } else {
                (rest.trim(), "")
            };

            let is_loopback = name.starts_with("lo") || desc.to_lowercase().contains("loopback");

            list.push(InterfaceInfo {
                index: idx,
                name: name.to_string(),
                description: if desc.is_empty() { name.to_string() } else { desc.to_string() },
                is_loopback,
                ip_addresses: Vec::new(),
            });
        }
    }
    list
}
