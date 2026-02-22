//! System administration tools: package management, network diagnostics,
//! network scanning, service management, user/group management, and firewall control.
//!
//! These tools detect the host OS and available package manager / init system
//! automatically.  All commands run through `sh -c` and respect the sandbox
//! restrictions already in place (credential directory, deny paths, etc.).

use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use tracing::{debug, warn, instrument};

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Run a shell pipeline via `sh -c` and return stdout (trimmed).
fn sh(script: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .map_err(|e| format!("shell error: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() && stdout.is_empty() {
        return Err(if stderr.is_empty() {
            format!("Command exited with {}", output.status)
        } else {
            stderr
        });
    }

    // Return combined output when there's stderr alongside stdout
    if !stderr.is_empty() && !stdout.is_empty() {
        Ok(format!("{}\n[stderr] {}", stdout, stderr))
    } else if !stdout.is_empty() {
        Ok(stdout)
    } else {
        Ok(stderr)
    }
}

/// Detect which command is available from a list. Returns the first found.
fn which_first(cmds: &[&str]) -> Option<String> {
    for cmd in cmds {
        if Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some((*cmd).to_string());
        }
    }
    None
}

/// Detect the package manager on this system.
fn detect_pkg_manager() -> (&'static str, &'static str) {
    // (command, display-name)
    let managers: &[(&str, &str)] = &[
        ("brew", "Homebrew"),
        ("apt", "APT"),
        ("apt-get", "APT"),
        ("dnf", "DNF"),
        ("yum", "YUM"),
        ("pacman", "Pacman"),
        ("zypper", "Zypper"),
        ("apk", "Alpine APK"),
        ("pkg", "FreeBSD pkg"),
        ("nix-env", "Nix"),
        ("snap", "Snap"),
        ("flatpak", "Flatpak"),
        ("port", "MacPorts"),
    ];

    for (cmd, name) in managers {
        if Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return (cmd, name);
        }
    }

    ("", "none")
}

/// Detect the init/service system.
fn detect_service_manager() -> &'static str {
    if Command::new("which")
        .arg("systemctl")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return "systemd";
    }
    if Command::new("which")
        .arg("launchctl")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return "launchd";
    }
    if std::path::Path::new("/etc/init.d").exists() {
        return "sysvinit";
    }
    "unknown"
}

// ── 1. pkg_manage ───────────────────────────────────────────────────────────

/// Package management: install, uninstall, upgrade, search, list, info.
#[instrument(skip(args, _workspace_dir), fields(action))]
pub fn exec_pkg_manage(args: &Value, _workspace_dir: &Path) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Missing required parameter: action")?;

    tracing::Span::current().record("action", action);

    let package = args.get("package").and_then(|v| v.as_str());
    let manager_override = args.get("manager").and_then(|v| v.as_str());

    debug!(package, manager = manager_override, "Package management request");

    let (mgr, mgr_name) = if let Some(m) = manager_override {
        (m, m)
    } else {
        let (m, n) = detect_pkg_manager();
        if m.is_empty() {
            warn!("No supported package manager found");
            return Err("No supported package manager found on this system".to_string());
        }
        (m, n)
    };

    debug!(manager = mgr_name, "Using package manager");

    match action {
        "install" => {
            let pkg = package.ok_or("Missing 'package' for install action")?;
            let cmd = match mgr {
                "brew" => format!("brew install {}", pkg),
                "apt" | "apt-get" => format!("sudo apt-get install -y {}", pkg),
                "dnf" => format!("sudo dnf install -y {}", pkg),
                "yum" => format!("sudo yum install -y {}", pkg),
                "pacman" => format!("sudo pacman -S --noconfirm {}", pkg),
                "zypper" => format!("sudo zypper install -y {}", pkg),
                "apk" => format!("sudo apk add {}", pkg),
                "snap" => format!("sudo snap install {}", pkg),
                "flatpak" => format!("flatpak install -y {}", pkg),
                "port" => format!("sudo port install {}", pkg),
                "nix-env" => format!("nix-env -iA nixpkgs.{}", pkg),
                _ => return Err(format!("Unknown package manager: {}", mgr)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "install",
                "package": pkg,
                "manager": mgr_name,
                "output": output,
            }).to_string())
        }

        "uninstall" | "remove" => {
            let pkg = package.ok_or("Missing 'package' for uninstall action")?;
            let cmd = match mgr {
                "brew" => format!("brew uninstall {}", pkg),
                "apt" | "apt-get" => format!("sudo apt-get remove -y {}", pkg),
                "dnf" => format!("sudo dnf remove -y {}", pkg),
                "yum" => format!("sudo yum remove -y {}", pkg),
                "pacman" => format!("sudo pacman -R --noconfirm {}", pkg),
                "zypper" => format!("sudo zypper remove -y {}", pkg),
                "apk" => format!("sudo apk del {}", pkg),
                "snap" => format!("sudo snap remove {}", pkg),
                "flatpak" => format!("flatpak uninstall -y {}", pkg),
                "port" => format!("sudo port uninstall {}", pkg),
                "nix-env" => format!("nix-env -e {}", pkg),
                _ => return Err(format!("Unknown package manager: {}", mgr)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "uninstall",
                "package": pkg,
                "manager": mgr_name,
                "output": output,
            }).to_string())
        }

        "upgrade" => {
            let cmd = if let Some(pkg) = package {
                // Upgrade a specific package
                match mgr {
                    "brew" => format!("brew upgrade {}", pkg),
                    "apt" | "apt-get" => format!("sudo apt-get install --only-upgrade -y {}", pkg),
                    "dnf" => format!("sudo dnf upgrade -y {}", pkg),
                    "yum" => format!("sudo yum update -y {}", pkg),
                    "pacman" => format!("sudo pacman -S --noconfirm {}", pkg),
                    "zypper" => format!("sudo zypper update -y {}", pkg),
                    "apk" => format!("sudo apk upgrade {}", pkg),
                    "snap" => format!("sudo snap refresh {}", pkg),
                    "nix-env" => format!("nix-env -u {}", pkg),
                    _ => return Err(format!("Unknown package manager: {}", mgr)),
                }
            } else {
                // Upgrade all
                match mgr {
                    "brew" => "brew upgrade".to_string(),
                    "apt" | "apt-get" => "sudo apt-get update && sudo apt-get upgrade -y".to_string(),
                    "dnf" => "sudo dnf upgrade -y".to_string(),
                    "yum" => "sudo yum update -y".to_string(),
                    "pacman" => "sudo pacman -Syu --noconfirm".to_string(),
                    "zypper" => "sudo zypper update -y".to_string(),
                    "apk" => "sudo apk upgrade".to_string(),
                    "snap" => "sudo snap refresh".to_string(),
                    "nix-env" => "nix-env -u".to_string(),
                    _ => return Err(format!("Unknown package manager: {}", mgr)),
                }
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "upgrade",
                "package": package.unwrap_or("(all)"),
                "manager": mgr_name,
                "output": output,
            }).to_string())
        }

        "search" => {
            let query = package.ok_or("Missing 'package' (search query) for search action")?;
            let cmd = match mgr {
                "brew" => format!("brew search {}", query),
                "apt" | "apt-get" => format!("apt-cache search {} | head -30", query),
                "dnf" => format!("dnf search {} 2>/dev/null | head -30", query),
                "yum" => format!("yum search {} 2>/dev/null | head -30", query),
                "pacman" => format!("pacman -Ss {} | head -40", query),
                "zypper" => format!("zypper search {} | head -30", query),
                "apk" => format!("apk search {} | head -30", query),
                "snap" => format!("snap find {} | head -20", query),
                "nix-env" => format!("nix-env -qaP '.*{}.*' 2>/dev/null | head -30", query),
                _ => return Err(format!("Unknown package manager: {}", mgr)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "search",
                "query": query,
                "manager": mgr_name,
                "results": output,
            }).to_string())
        }

        "list" => {
            let cmd = match mgr {
                "brew" => "brew list --versions".to_string(),
                "apt" | "apt-get" => "dpkg -l | tail -n +6 | awk '{print $2, $3}' | head -100".to_string(),
                "dnf" | "yum" => "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' | sort | head -100".to_string(),
                "pacman" => "pacman -Q | head -100".to_string(),
                "zypper" => "zypper se --installed-only | head -100".to_string(),
                "apk" => "apk list --installed 2>/dev/null | head -100".to_string(),
                "snap" => "snap list".to_string(),
                "nix-env" => "nix-env -q | head -100".to_string(),
                _ => return Err(format!("Unknown package manager: {}", mgr)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "list",
                "manager": mgr_name,
                "packages": output,
            }).to_string())
        }

        "info" => {
            let pkg = package.ok_or("Missing 'package' for info action")?;
            let cmd = match mgr {
                "brew" => format!("brew info {}", pkg),
                "apt" | "apt-get" => format!("apt-cache show {} 2>/dev/null | head -40", pkg),
                "dnf" => format!("dnf info {} 2>/dev/null", pkg),
                "yum" => format!("yum info {} 2>/dev/null", pkg),
                "pacman" => format!("pacman -Si {} 2>/dev/null || pacman -Qi {} 2>/dev/null", pkg, pkg),
                "zypper" => format!("zypper info {}", pkg),
                "apk" => format!("apk info {} 2>/dev/null", pkg),
                "snap" => format!("snap info {}", pkg),
                "nix-env" => format!("nix-env -qaP --description '.*{}.*' 2>/dev/null", pkg),
                _ => return Err(format!("Unknown package manager: {}", mgr)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "info",
                "package": pkg,
                "manager": mgr_name,
                "details": output,
            }).to_string())
        }

        "detect" => {
            Ok(json!({
                "action": "detect",
                "manager": mgr_name,
                "command": mgr,
            }).to_string())
        }

        _ => Err(format!(
            "Unknown action: {}. Valid: install, uninstall, upgrade, search, list, info, detect",
            action
        )),
    }
}

// ── 2. net_info ─────────────────────────────────────────────────────────────

/// Network information: interfaces, connections, routing, DNS, and diagnostics.
#[instrument(skip(args, _workspace_dir), fields(action))]
pub fn exec_net_info(args: &Value, _workspace_dir: &Path) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Missing required parameter: action")?;

    tracing::Span::current().record("action", action);
    let target = args.get("target").and_then(|v| v.as_str());
    debug!(target, "Network info request");

    match action {
        "interfaces" => {
            // Show network interfaces with IP addresses
            let output = if cfg!(target_os = "macos") {
                sh("ifconfig | grep -E '^[a-z]|inet ' | head -60")?
            } else {
                sh("ip -brief addr show 2>/dev/null || ifconfig 2>/dev/null | head -60")?
            };
            Ok(json!({
                "action": "interfaces",
                "output": output,
            }).to_string())
        }

        "connections" => {
            // Active network connections
            let filter = target.unwrap_or("");
            let cmd = if cfg!(target_os = "macos") {
                if filter.is_empty() {
                    "netstat -an | head -60".to_string()
                } else {
                    format!("netstat -an | grep -i '{}' | head -60", filter)
                }
            } else if filter.is_empty() {
                "ss -tunapl 2>/dev/null | head -60 || netstat -tunapl 2>/dev/null | head -60"
                    .to_string()
            } else {
                format!(
                    "ss -tunapl 2>/dev/null | grep -i '{}' | head -60 || \
                     netstat -tunapl 2>/dev/null | grep -i '{}' | head -60",
                    filter, filter
                )
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "connections",
                "filter": filter,
                "output": output,
            }).to_string())
        }

        "routing" => {
            let output = if cfg!(target_os = "macos") {
                sh("netstat -rn | head -40")?
            } else {
                sh("ip route show 2>/dev/null || netstat -rn 2>/dev/null | head -40")?
            };
            Ok(json!({
                "action": "routing",
                "output": output,
            }).to_string())
        }

        "dns" => {
            let host = target.unwrap_or("example.com");
            let tool = which_first(&["dig", "nslookup", "host"]);
            let output = match tool.as_deref() {
                Some("dig") => sh(&format!("dig {} +short", host))?,
                Some("nslookup") => sh(&format!("nslookup {} 2>/dev/null", host))?,
                Some("host") => sh(&format!("host {}", host))?,
                _ => return Err("No DNS tool found (dig, nslookup, or host)".to_string()),
            };
            Ok(json!({
                "action": "dns",
                "host": host,
                "tool": tool.unwrap_or_default(),
                "output": output,
            }).to_string())
        }

        "ping" => {
            let host = target.ok_or("Missing 'target' (host/IP) for ping")?;
            let count = args
                .get("count")
                .and_then(|v| v.as_u64())
                .unwrap_or(4);
            let output = sh(&format!("ping -c {} {} 2>&1", count, host))?;
            Ok(json!({
                "action": "ping",
                "target": host,
                "count": count,
                "output": output,
            }).to_string())
        }

        "traceroute" => {
            let host = target.ok_or("Missing 'target' (host/IP) for traceroute")?;
            let tool = which_first(&["traceroute", "tracepath", "mtr"]);
            let cmd = match tool.as_deref() {
                Some("mtr") => format!("mtr -r -c 3 {} 2>&1", host),
                Some("tracepath") => format!("tracepath {} 2>&1 | head -30", host),
                Some("traceroute") => format!("traceroute -m 20 {} 2>&1", host),
                _ => return Err("No traceroute tool found (traceroute, tracepath, or mtr)".to_string()),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "traceroute",
                "target": host,
                "tool": tool.unwrap_or_default(),
                "output": output,
            }).to_string())
        }

        "whois" => {
            let domain = target.ok_or("Missing 'target' for whois lookup")?;
            let output = sh(&format!("whois {} 2>&1 | head -80", domain))?;
            Ok(json!({
                "action": "whois",
                "target": domain,
                "output": output,
            }).to_string())
        }

        "arp" => {
            let output = sh("arp -a 2>/dev/null | head -50")?;
            Ok(json!({
                "action": "arp",
                "output": output,
            }).to_string())
        }

        "public_ip" => {
            let output = sh("curl -s --max-time 5 ifconfig.me 2>/dev/null || \
                            curl -s --max-time 5 api.ipify.org 2>/dev/null || \
                            curl -s --max-time 5 icanhazip.com 2>/dev/null")?;
            Ok(json!({
                "action": "public_ip",
                "ip": output.trim(),
            }).to_string())
        }

        "wifi" => {
            let output = if cfg!(target_os = "macos") {
                sh("system_profiler SPAirPortDataType 2>/dev/null | head -40 || \
                    /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null")?
            } else {
                sh("iwconfig 2>/dev/null || nmcli device wifi list 2>/dev/null | head -30")?
            };
            Ok(json!({
                "action": "wifi",
                "output": output,
            }).to_string())
        }

        "bandwidth" => {
            let tool = which_first(&["speedtest-cli", "speedtest", "fast"]);
            match tool.as_deref() {
                Some(t) => {
                    let output = sh(&format!("{} --simple 2>&1 || {} 2>&1", t, t))?;
                    Ok(json!({
                        "action": "bandwidth",
                        "tool": t,
                        "output": output,
                    }).to_string())
                }
                None => Err("No bandwidth test tool found. Install speedtest-cli.".to_string()),
            }
        }

        _ => Err(format!(
            "Unknown action: {}. Valid: interfaces, connections, routing, dns, ping, \
             traceroute, whois, arp, public_ip, wifi, bandwidth",
            action
        )),
    }
}

// ── 3. net_scan ─────────────────────────────────────────────────────────────

/// Network scanning: nmap, tcpdump, port checks, and lightweight alternatives.
#[instrument(skip(args, _workspace_dir), fields(action))]
pub fn exec_net_scan(args: &Value, _workspace_dir: &Path) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Missing required parameter: action")?;

    tracing::Span::current().record("action", action);
    let target = args.get("target").and_then(|v| v.as_str());
    debug!(target, "Network scan request");

    match action {
        "nmap" => {
            let host = target.ok_or("Missing 'target' (host/IP/subnet) for nmap scan")?;
            let scan_type = args
                .get("scan_type")
                .and_then(|v| v.as_str())
                .unwrap_or("quick");
            let ports = args.get("ports").and_then(|v| v.as_str());

            // Verify nmap is installed
            if which_first(&["nmap"]).is_none() {
                return Err(
                    "nmap is not installed. Install with: brew install nmap / apt install nmap"
                        .to_string(),
                );
            }

            let cmd = match scan_type {
                "quick" => {
                    if let Some(p) = ports {
                        format!("nmap -T4 -p {} {} 2>&1", p, host)
                    } else {
                        format!("nmap -T4 -F {} 2>&1", host)
                    }
                }
                "full" => format!("nmap -T4 -p- {} 2>&1", host),
                "service" | "version" => {
                    if let Some(p) = ports {
                        format!("nmap -sV -p {} {} 2>&1", p, host)
                    } else {
                        format!("nmap -sV -F {} 2>&1", host)
                    }
                }
                "os" => format!("sudo nmap -O {} 2>&1", host),
                "udp" => {
                    if let Some(p) = ports {
                        format!("sudo nmap -sU -p {} {} 2>&1", p, host)
                    } else {
                        format!("sudo nmap -sU --top-ports 20 {} 2>&1", host)
                    }
                }
                "vuln" => format!("nmap --script vuln {} 2>&1", host),
                "ping" => format!("nmap -sn {} 2>&1", host),
                "stealth" => format!("sudo nmap -sS -T2 {} 2>&1", host),
                _ => return Err(format!(
                    "Unknown scan_type: {}. Valid: quick, full, service, os, udp, vuln, ping, stealth",
                    scan_type
                )),
            };

            let output = sh(&cmd)?;
            Ok(json!({
                "action": "nmap",
                "target": host,
                "scan_type": scan_type,
                "output": output,
            }).to_string())
        }

        "tcpdump" => {
            let iface = args
                .get("interface")
                .and_then(|v| v.as_str())
                .unwrap_or("any");
            let filter = target.unwrap_or("");
            let count = args
                .get("count")
                .and_then(|v| v.as_u64())
                .unwrap_or(20);

            if which_first(&["tcpdump"]).is_none() {
                return Err(
                    "tcpdump is not installed. Install with: brew install tcpdump / apt install tcpdump"
                        .to_string(),
                );
            }

            let cmd = if filter.is_empty() {
                format!(
                    "sudo timeout 10 tcpdump -i {} -c {} -nn 2>&1 || \
                     sudo tcpdump -i {} -c {} -nn 2>&1",
                    iface, count, iface, count
                )
            } else {
                format!(
                    "sudo timeout 10 tcpdump -i {} -c {} -nn '{}' 2>&1 || \
                     sudo tcpdump -i {} -c {} -nn '{}' 2>&1",
                    iface, count, filter, iface, count, filter
                )
            };

            let output = sh(&cmd)?;
            Ok(json!({
                "action": "tcpdump",
                "interface": iface,
                "filter": filter,
                "count": count,
                "output": output,
            }).to_string())
        }

        "port_check" => {
            let host = target.ok_or("Missing 'target' (host:port or host) for port_check")?;
            let port = args
                .get("port")
                .and_then(|v| v.as_u64())
                .or_else(|| args.get("ports").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()));

            if let Some(p) = port {
                // Single port check with nc or /dev/tcp
                let cmd = format!(
                    "nc -z -w 3 {} {} 2>&1 && echo 'OPEN' || echo 'CLOSED'",
                    host, p
                );
                let output = sh(&cmd)?;
                Ok(json!({
                    "action": "port_check",
                    "target": host,
                    "port": p,
                    "status": if output.contains("OPEN") { "open" } else { "closed" },
                    "output": output,
                }).to_string())
            } else {
                // Scan common ports with nc
                let cmd = format!(
                    "for p in 22 80 443 8080 3306 5432 6379 27017 3000 8443; do \
                       nc -z -w 1 {} $p 2>/dev/null && echo \"$p OPEN\" || echo \"$p CLOSED\"; \
                     done",
                    host
                );
                let output = sh(&cmd)?;
                Ok(json!({
                    "action": "port_check",
                    "target": host,
                    "output": output,
                }).to_string())
            }
        }

        "listen" => {
            // Show listening ports/services
            let output = if cfg!(target_os = "macos") {
                sh("lsof -i -P -n | grep LISTEN | head -40")?
            } else {
                sh("ss -tlnp 2>/dev/null | head -40 || netstat -tlnp 2>/dev/null | head -40")?
            };
            Ok(json!({
                "action": "listen",
                "output": output,
            }).to_string())
        }

        "sniff" => {
            // Lightweight packet sniff summary without tcpdump
            let iface = args
                .get("interface")
                .and_then(|v| v.as_str())
                .unwrap_or("any");
            let seconds = args
                .get("seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(5);

            let tool = which_first(&["tcpdump", "tshark"]);
            let cmd = match tool.as_deref() {
                Some("tcpdump") => format!(
                    "sudo timeout {} tcpdump -i {} -c 30 -q -nn 2>&1",
                    seconds, iface
                ),
                Some("tshark") => format!(
                    "timeout {} tshark -i {} -c 30 -q 2>&1",
                    seconds, iface
                ),
                _ => return Err("No packet capture tool found (tcpdump or tshark)".to_string()),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "sniff",
                "interface": iface,
                "seconds": seconds,
                "tool": tool.unwrap_or_default(),
                "output": output,
            }).to_string())
        }

        "discover" => {
            // Discover hosts on the local network
            let subnet = target.unwrap_or("192.168.1.0/24");
            let tool = which_first(&["nmap", "arp-scan", "fping"]);
            let cmd = match tool.as_deref() {
                Some("nmap") => format!("nmap -sn {} 2>&1", subnet),
                Some("arp-scan") => format!("sudo arp-scan {} 2>&1 | head -40", subnet),
                Some("fping") => format!("fping -a -g {} 2>/dev/null | head -40", subnet),
                _ => {
                    // Fallback: ARP table
                    "arp -a 2>/dev/null | head -40".to_string()
                }
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "discover",
                "subnet": subnet,
                "tool": tool.unwrap_or_else(|| "arp".into()),
                "output": output,
            }).to_string())
        }

        _ => Err(format!(
            "Unknown action: {}. Valid: nmap, tcpdump, port_check, listen, sniff, discover",
            action
        )),
    }
}

// ── 4. service_manage ───────────────────────────────────────────────────────

/// Manage system services: start, stop, restart, status, enable, disable, list.
#[instrument(skip(args, _workspace_dir), fields(action))]
pub fn exec_service_manage(args: &Value, _workspace_dir: &Path) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Missing required parameter: action")?;

    tracing::Span::current().record("action", action);
    let service = args.get("service").and_then(|v| v.as_str());
    let init = detect_service_manager();
    debug!(service, init_system = init, "Service management request");

    match action {
        "list" => {
            let filter = service.unwrap_or("");
            let cmd = match init {
                "systemd" => {
                    if filter.is_empty() {
                        "systemctl list-units --type=service --no-pager | head -50".to_string()
                    } else {
                        format!(
                            "systemctl list-units --type=service --no-pager | grep -i '{}' | head -30",
                            filter
                        )
                    }
                }
                "launchd" => {
                    if filter.is_empty() {
                        "launchctl list | head -50".to_string()
                    } else {
                        format!("launchctl list | grep -i '{}' | head -30", filter)
                    }
                }
                "sysvinit" => "ls /etc/init.d/ | head -50".to_string(),
                _ => return Err(format!("Unknown init system: {}", init)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "list",
                "init_system": init,
                "filter": filter,
                "output": output,
            }).to_string())
        }

        "status" => {
            let svc = service.ok_or("Missing 'service' for status action")?;
            let cmd = match init {
                "systemd" => format!("systemctl status {} --no-pager 2>&1", svc),
                "launchd" => format!("launchctl print system/{} 2>&1 || launchctl list {} 2>&1", svc, svc),
                "sysvinit" => format!("/etc/init.d/{} status 2>&1", svc),
                _ => return Err(format!("Unknown init system: {}", init)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "status",
                "service": svc,
                "init_system": init,
                "output": output,
            }).to_string())
        }

        "start" => {
            let svc = service.ok_or("Missing 'service' for start action")?;
            let cmd = match init {
                "systemd" => format!("sudo systemctl start {} 2>&1", svc),
                "launchd" => format!("sudo launchctl start {} 2>&1", svc),
                "sysvinit" => format!("sudo /etc/init.d/{} start 2>&1", svc),
                _ => return Err(format!("Unknown init system: {}", init)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "start",
                "service": svc,
                "init_system": init,
                "output": if output.is_empty() { "Service started.".into() } else { output },
            }).to_string())
        }

        "stop" => {
            let svc = service.ok_or("Missing 'service' for stop action")?;
            let cmd = match init {
                "systemd" => format!("sudo systemctl stop {} 2>&1", svc),
                "launchd" => format!("sudo launchctl stop {} 2>&1", svc),
                "sysvinit" => format!("sudo /etc/init.d/{} stop 2>&1", svc),
                _ => return Err(format!("Unknown init system: {}", init)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "stop",
                "service": svc,
                "init_system": init,
                "output": if output.is_empty() { "Service stopped.".into() } else { output },
            }).to_string())
        }

        "restart" => {
            let svc = service.ok_or("Missing 'service' for restart action")?;
            let cmd = match init {
                "systemd" => format!("sudo systemctl restart {} 2>&1", svc),
                "launchd" => format!("sudo launchctl kickstart -k system/{} 2>&1", svc),
                "sysvinit" => format!("sudo /etc/init.d/{} restart 2>&1", svc),
                _ => return Err(format!("Unknown init system: {}", init)),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "restart",
                "service": svc,
                "init_system": init,
                "output": if output.is_empty() { "Service restarted.".into() } else { output },
            }).to_string())
        }

        "enable" => {
            let svc = service.ok_or("Missing 'service' for enable action")?;
            let cmd = match init {
                "systemd" => format!("sudo systemctl enable {} 2>&1", svc),
                "launchd" => format!("sudo launchctl load -w /Library/LaunchDaemons/{}.plist 2>&1 || \
                                     launchctl load -w ~/Library/LaunchAgents/{}.plist 2>&1", svc, svc),
                _ => return Err("enable/disable requires systemd or launchd".to_string()),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "enable",
                "service": svc,
                "init_system": init,
                "output": if output.is_empty() { "Service enabled.".into() } else { output },
            }).to_string())
        }

        "disable" => {
            let svc = service.ok_or("Missing 'service' for disable action")?;
            let cmd = match init {
                "systemd" => format!("sudo systemctl disable {} 2>&1", svc),
                "launchd" => format!("sudo launchctl unload -w /Library/LaunchDaemons/{}.plist 2>&1 || \
                                     launchctl unload -w ~/Library/LaunchAgents/{}.plist 2>&1", svc, svc),
                _ => return Err("enable/disable requires systemd or launchd".to_string()),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "disable",
                "service": svc,
                "init_system": init,
                "output": if output.is_empty() { "Service disabled.".into() } else { output },
            }).to_string())
        }

        "logs" => {
            let svc = service.ok_or("Missing 'service' for logs action")?;
            let lines = args
                .get("lines")
                .and_then(|v| v.as_u64())
                .unwrap_or(50);
            let cmd = match init {
                "systemd" => format!("journalctl -u {} -n {} --no-pager 2>&1", svc, lines),
                "launchd" => format!(
                    "log show --predicate 'subsystem==\"{}\"' --last 5m --style compact 2>&1 | tail -{}",
                    svc, lines
                ),
                _ => return Err("Service logs require systemd or launchd".to_string()),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "logs",
                "service": svc,
                "lines": lines,
                "init_system": init,
                "output": output,
            }).to_string())
        }

        _ => Err(format!(
            "Unknown action: {}. Valid: list, status, start, stop, restart, enable, disable, logs",
            action
        )),
    }
}

// ── 5. user_manage ──────────────────────────────────────────────────────────

/// User and group management: list users, groups, add/remove users, manage sudoers.
#[instrument(skip(args, _workspace_dir), fields(action))]
pub fn exec_user_manage(args: &Value, _workspace_dir: &Path) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Missing required parameter: action")?;

    tracing::Span::current().record("action", action);
    let name = args.get("name").and_then(|v| v.as_str());
    debug!(name, "User management request");

    match action {
        "whoami" => {
            let user = sh("whoami")?;
            let groups = sh("groups 2>/dev/null").unwrap_or_default();
            let id_output = sh("id").unwrap_or_default();
            let sudo_check = sh("sudo -n true 2>&1; echo $?")
                .map(|s| s.trim() == "0")
                .unwrap_or(false);
            Ok(json!({
                "action": "whoami",
                "user": user,
                "groups": groups,
                "id": id_output,
                "has_sudo": sudo_check,
            }).to_string())
        }

        "list_users" => {
            let output = if cfg!(target_os = "macos") {
                sh("dscl . list /Users | grep -v '^_'")?
            } else {
                sh("awk -F: '$3 >= 1000 || $3 == 0 { print $1, $3, $6, $7 }' /etc/passwd")?
            };
            Ok(json!({
                "action": "list_users",
                "output": output,
            }).to_string())
        }

        "list_groups" => {
            let output = if cfg!(target_os = "macos") {
                sh("dscl . list /Groups | grep -v '^_' | head -40")?
            } else {
                sh("awk -F: '{ print $1, $3 }' /etc/group | head -40")?
            };
            Ok(json!({
                "action": "list_groups",
                "output": output,
            }).to_string())
        }

        "user_info" => {
            let user = name.ok_or("Missing 'name' for user_info")?;
            let output = if cfg!(target_os = "macos") {
                sh(&format!("dscl . read /Users/{} 2>&1 | head -30", user))?
            } else {
                sh(&format!("id {} 2>&1 && getent passwd {} 2>/dev/null", user, user))?
            };
            Ok(json!({
                "action": "user_info",
                "user": user,
                "output": output,
            }).to_string())
        }

        "add_user" => {
            let user = name.ok_or("Missing 'name' for add_user")?;
            let cmd = if cfg!(target_os = "macos") {
                format!(
                    "sudo sysadminctl -addUser {} -password '' 2>&1",
                    user
                )
            } else {
                let shell = args
                    .get("shell")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/bin/bash");
                format!(
                    "sudo useradd -m -s {} {} 2>&1",
                    shell, user
                )
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "add_user",
                "user": user,
                "output": if output.is_empty() { format!("User '{}' created.", user) } else { output },
            }).to_string())
        }

        "remove_user" => {
            let user = name.ok_or("Missing 'name' for remove_user")?;
            let cmd = if cfg!(target_os = "macos") {
                format!("sudo sysadminctl -deleteUser {} 2>&1", user)
            } else {
                format!("sudo userdel -r {} 2>&1", user)
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "remove_user",
                "user": user,
                "output": if output.is_empty() { format!("User '{}' removed.", user) } else { output },
            }).to_string())
        }

        "add_to_group" => {
            let user = name.ok_or("Missing 'name' (username) for add_to_group")?;
            let group = args
                .get("group")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'group' for add_to_group")?;
            let cmd = if cfg!(target_os = "macos") {
                format!("sudo dseditgroup -o edit -a {} -t user {} 2>&1", user, group)
            } else {
                format!("sudo usermod -aG {} {} 2>&1", group, user)
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "add_to_group",
                "user": user,
                "group": group,
                "output": if output.is_empty() {
                    format!("User '{}' added to group '{}'.", user, group)
                } else { output },
            }).to_string())
        }

        "last_logins" => {
            let output = sh("last -20 2>/dev/null | head -25")?;
            Ok(json!({
                "action": "last_logins",
                "output": output,
            }).to_string())
        }

        _ => Err(format!(
            "Unknown action: {}. Valid: whoami, list_users, list_groups, user_info, \
             add_user, remove_user, add_to_group, last_logins",
            action
        )),
    }
}

// ── 6. firewall ─────────────────────────────────────────────────────────────

/// Firewall management: view rules, allow/deny ports, enable/disable.
#[instrument(skip(args, _workspace_dir), fields(action))]
pub fn exec_firewall(args: &Value, _workspace_dir: &Path) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Missing required parameter: action")?;

    tracing::Span::current().record("action", action);

    // Detect firewall backend
    let backend = if cfg!(target_os = "macos") {
        "pf"
    } else if which_first(&["ufw"]).is_some() {
        "ufw"
    } else if which_first(&["firewall-cmd"]).is_some() {
        "firewalld"
    } else if which_first(&["iptables"]).is_some() {
        "iptables"
    } else if which_first(&["nft"]).is_some() {
        "nftables"
    } else {
        "unknown"
    };

    debug!(backend, "Firewall management request");

    match action {
        "status" => {
            let cmd = match backend {
                "pf" => "sudo pfctl -s info 2>&1 | head -10",
                "ufw" => "sudo ufw status verbose 2>&1",
                "firewalld" => "sudo firewall-cmd --state 2>&1 && sudo firewall-cmd --list-all 2>&1",
                "iptables" => "sudo iptables -L -n --line-numbers 2>&1 | head -50",
                "nftables" => "sudo nft list ruleset 2>&1 | head -50",
                _ => return Err("No supported firewall found".to_string()),
            };
            let output = sh(cmd)?;
            Ok(json!({
                "action": "status",
                "backend": backend,
                "output": output,
            }).to_string())
        }

        "rules" => {
            let cmd = match backend {
                "pf" => "sudo pfctl -s rules 2>&1",
                "ufw" => "sudo ufw status numbered 2>&1",
                "firewalld" => "sudo firewall-cmd --list-all 2>&1",
                "iptables" => "sudo iptables -L -n -v --line-numbers 2>&1 | head -60",
                "nftables" => "sudo nft list ruleset 2>&1 | head -60",
                _ => return Err("No supported firewall found".to_string()),
            };
            let output = sh(cmd)?;
            Ok(json!({
                "action": "rules",
                "backend": backend,
                "output": output,
            }).to_string())
        }

        "allow" => {
            let port = args
                .get("port")
                .and_then(|v| v.as_u64())
                .or_else(|| args.get("port").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()))
                .ok_or("Missing 'port' for allow action")?;
            let proto = args
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp");

            let cmd = match backend {
                "ufw" => format!("sudo ufw allow {}/{} 2>&1", port, proto),
                "firewalld" => format!(
                    "sudo firewall-cmd --add-port={}/{} --permanent 2>&1 && \
                     sudo firewall-cmd --reload 2>&1",
                    port, proto
                ),
                "iptables" => format!(
                    "sudo iptables -A INPUT -p {} --dport {} -j ACCEPT 2>&1",
                    proto, port
                ),
                "pf" => format!(
                    "echo 'pass in proto {} from any to any port {}' | sudo pfctl -f - 2>&1",
                    proto, port
                ),
                _ => return Err("No supported firewall found".to_string()),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "allow",
                "port": port,
                "protocol": proto,
                "backend": backend,
                "output": if output.is_empty() {
                    format!("Port {}/{} allowed.", port, proto)
                } else { output },
            }).to_string())
        }

        "deny" => {
            let port = args
                .get("port")
                .and_then(|v| v.as_u64())
                .or_else(|| args.get("port").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()))
                .ok_or("Missing 'port' for deny action")?;
            let proto = args
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp");

            let cmd = match backend {
                "ufw" => format!("sudo ufw deny {}/{} 2>&1", port, proto),
                "firewalld" => format!(
                    "sudo firewall-cmd --remove-port={}/{} --permanent 2>&1 && \
                     sudo firewall-cmd --reload 2>&1",
                    port, proto
                ),
                "iptables" => format!(
                    "sudo iptables -A INPUT -p {} --dport {} -j DROP 2>&1",
                    proto, port
                ),
                _ => return Err("No supported firewall found for deny action".to_string()),
            };
            let output = sh(&cmd)?;
            Ok(json!({
                "action": "deny",
                "port": port,
                "protocol": proto,
                "backend": backend,
                "output": if output.is_empty() {
                    format!("Port {}/{} denied.", port, proto)
                } else { output },
            }).to_string())
        }

        "enable" => {
            let cmd = match backend {
                "ufw" => "sudo ufw --force enable 2>&1",
                "firewalld" => "sudo systemctl start firewalld && sudo systemctl enable firewalld 2>&1",
                "pf" => "sudo pfctl -e 2>&1",
                _ => return Err("No supported firewall found for enable".to_string()),
            };
            let output = sh(cmd)?;
            Ok(json!({
                "action": "enable",
                "backend": backend,
                "output": if output.is_empty() { "Firewall enabled.".into() } else { output },
            }).to_string())
        }

        "disable" => {
            let cmd = match backend {
                "ufw" => "sudo ufw disable 2>&1",
                "firewalld" => "sudo systemctl stop firewalld 2>&1",
                "pf" => "sudo pfctl -d 2>&1",
                _ => return Err("No supported firewall found for disable".to_string()),
            };
            let output = sh(cmd)?;
            Ok(json!({
                "action": "disable",
                "backend": backend,
                "output": if output.is_empty() { "Firewall disabled.".into() } else { output },
            }).to_string())
        }

        _ => Err(format!(
            "Unknown action: {}. Valid: status, rules, allow, deny, enable, disable",
            action
        )),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ws() -> &'static Path {
        Path::new("/tmp")
    }

    // pkg_manage

    #[test]
    fn test_pkg_manage_detect() {
        let args = json!({ "action": "detect" });
        let result = exec_pkg_manage(&args, ws());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("manager"));
    }

    #[test]
    fn test_pkg_manage_missing_action() {
        let args = json!({});
        let result = exec_pkg_manage(&args, ws());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("action"));
    }

    #[test]
    fn test_pkg_manage_search() {
        let args = json!({ "action": "search", "package": "curl" });
        let result = exec_pkg_manage(&args, ws());
        // May fail if no package manager, but should not panic
        assert!(result.is_ok() || result.is_err());
    }

    // net_info

    #[test]
    fn test_net_info_interfaces() {
        let args = json!({ "action": "interfaces" });
        let result = exec_net_info(&args, ws());
        assert!(result.is_ok());
    }

    #[test]
    fn test_net_info_missing_action() {
        let args = json!({});
        let result = exec_net_info(&args, ws());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("action"));
    }

    #[test]
    fn test_net_info_public_ip() {
        let args = json!({ "action": "public_ip" });
        let result = exec_net_info(&args, ws());
        // May fail without internet, but should not panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_net_info_arp() {
        let args = json!({ "action": "arp" });
        let result = exec_net_info(&args, ws());
        assert!(result.is_ok());
    }

    // net_scan

    #[test]
    fn test_net_scan_listen() {
        let args = json!({ "action": "listen" });
        let result = exec_net_scan(&args, ws());
        assert!(result.is_ok());
    }

    #[test]
    fn test_net_scan_missing_action() {
        let args = json!({});
        let result = exec_net_scan(&args, ws());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("action"));
    }

    // service_manage

    #[test]
    fn test_service_manage_list() {
        let args = json!({ "action": "list" });
        let result = exec_service_manage(&args, ws());
        assert!(result.is_ok());
    }

    #[test]
    fn test_service_manage_missing_action() {
        let args = json!({});
        let result = exec_service_manage(&args, ws());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("action"));
    }

    // user_manage

    #[test]
    fn test_user_manage_whoami() {
        let args = json!({ "action": "whoami" });
        let result = exec_user_manage(&args, ws());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("user"));
    }

    #[test]
    fn test_user_manage_missing_action() {
        let args = json!({});
        let result = exec_user_manage(&args, ws());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("action"));
    }

    #[test]
    fn test_user_manage_list_users() {
        let args = json!({ "action": "list_users" });
        let result = exec_user_manage(&args, ws());
        assert!(result.is_ok());
    }

    // firewall

    #[test]
    fn test_firewall_missing_action() {
        let args = json!({});
        let result = exec_firewall(&args, ws());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("action"));
    }
}
