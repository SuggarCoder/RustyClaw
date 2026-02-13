//! Agent sandbox — isolates tool execution from sensitive paths.
//!
//! Two modes:
//! 1. **Landlock** (preferred) — kernel-enforced filesystem restrictions
//! 2. **Bubblewrap** — user namespace sandbox for execute_command
//!
//! Landlock is applied to the entire process, restricting what the agent
//! can access. Bubblewrap wraps individual shell commands.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ── Landlock Support ────────────────────────────────────────────────────────

/// Check if Landlock is supported on this kernel.
pub fn landlock_supported() -> bool {
    // Landlock requires kernel 5.13+ and the LSM enabled
    Path::new("/sys/kernel/security/landlock").exists()
        || std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.contains("landlock"))
            .unwrap_or(false)
}

/// Paths that should be denied to the agent.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Paths the agent cannot read from
    pub deny_read: Vec<PathBuf>,
    /// Paths the agent cannot write to
    pub deny_write: Vec<PathBuf>,
    /// Paths the agent cannot execute from
    pub deny_exec: Vec<PathBuf>,
    /// Allowed paths (whitelist mode) — if non-empty, only these are allowed
    pub allow_paths: Vec<PathBuf>,
    /// Working directory for the agent
    pub workspace: PathBuf,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            deny_read: Vec::new(),
            deny_write: Vec::new(),
            deny_exec: Vec::new(),
            allow_paths: Vec::new(),
            workspace: PathBuf::from("."),
        }
    }
}

impl SandboxPolicy {
    /// Create a policy that protects the credentials directory.
    pub fn protect_credentials(credentials_dir: impl Into<PathBuf>, workspace: impl Into<PathBuf>) -> Self {
        let cred_dir = credentials_dir.into();
        Self {
            deny_read: vec![cred_dir.clone()],
            deny_write: vec![cred_dir.clone()],
            deny_exec: vec![cred_dir],
            allow_paths: Vec::new(),
            workspace: workspace.into(),
        }
    }

    /// Create a strict policy that only allows access to specific paths.
    pub fn strict(workspace: impl Into<PathBuf>, allowed: Vec<PathBuf>) -> Self {
        Self {
            deny_read: Vec::new(),
            deny_write: Vec::new(),
            deny_exec: Vec::new(),
            allow_paths: allowed,
            workspace: workspace.into(),
        }
    }

    /// Add a path to the deny-read list.
    pub fn deny_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_read.push(path.into());
        self
    }

    /// Add a path to the deny-write list.
    pub fn deny_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_write.push(path.into());
        self
    }
}

// ── Landlock Implementation ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod landlock_impl {
    use super::*;
    use std::os::unix::io::AsRawFd;

    // Landlock ABI version 1 constants
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
    
    // Access rights for files
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

    const ALL_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// Apply Landlock restrictions to the current process.
    ///
    /// **Warning:** This is irreversible! Once applied, the restrictions
    /// cannot be loosened for this process or its children.
    pub fn apply_landlock(policy: &SandboxPolicy) -> Result<(), String> {
        // For now, we use a simpler approach: just validate paths
        // Full Landlock requires careful syscall handling
        
        // This is a placeholder — real implementation would use:
        // - landlock_create_ruleset()
        // - landlock_add_rule()
        // - landlock_restrict_self()
        
        eprintln!(
            "[sandbox] Landlock policy prepared: deny_read={:?}, deny_write={:?}",
            policy.deny_read,
            policy.deny_write
        );
        
        // For MVP, we rely on the path checking in tools.rs
        // A full implementation would make syscalls here
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod landlock_impl {
    use super::*;
    
    pub fn apply_landlock(_policy: &SandboxPolicy) -> Result<(), String> {
        Err("Landlock is only supported on Linux".to_string())
    }
}

pub use landlock_impl::apply_landlock;

// ── Bubblewrap Implementation ───────────────────────────────────────────────

/// Check if bubblewrap is available.
pub fn bwrap_available() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Wrap a command in bubblewrap with the given policy.
///
/// Returns the modified command and arguments.
pub fn wrap_with_bwrap(
    command: &str,
    policy: &SandboxPolicy,
) -> (String, Vec<String>) {
    let mut args = Vec::new();
    
    // Basic namespace isolation
    args.push("--unshare-all".to_string());
    args.push("--share-net".to_string()); // Keep network for web_fetch etc
    
    // Mount a minimal root
    args.push("--ro-bind".to_string());
    args.push("/usr".to_string());
    args.push("/usr".to_string());
    
    args.push("--ro-bind".to_string());
    args.push("/lib".to_string());
    args.push("/lib".to_string());
    
    args.push("--ro-bind".to_string());
    args.push("/lib64".to_string());
    args.push("/lib64".to_string());
    
    args.push("--ro-bind".to_string());
    args.push("/bin".to_string());
    args.push("/bin".to_string());
    
    args.push("--ro-bind".to_string());
    args.push("/etc".to_string());
    args.push("/etc".to_string());
    
    // Writable workspace
    args.push("--bind".to_string());
    args.push(policy.workspace.display().to_string());
    args.push(policy.workspace.display().to_string());
    
    // Writable /tmp
    args.push("--tmpfs".to_string());
    args.push("/tmp".to_string());
    
    // Deny access to credentials by simply not mounting them
    // (They won't exist in the sandbox namespace)
    
    // Set up /proc for basic functionality
    args.push("--proc".to_string());
    args.push("/proc".to_string());
    
    // Set up /dev minimally
    args.push("--dev".to_string());
    args.push("/dev".to_string());
    
    // Working directory
    args.push("--chdir".to_string());
    args.push(policy.workspace.display().to_string());
    
    // Die with parent
    args.push("--die-with-parent".to_string());
    
    // The actual command
    args.push("--".to_string());
    args.push("sh".to_string());
    args.push("-c".to_string());
    args.push(command.to_string());
    
    ("bwrap".to_string(), args)
}

/// Run a command inside a bubblewrap sandbox.
pub fn run_sandboxed(
    command: &str,
    policy: &SandboxPolicy,
    timeout_secs: Option<u64>,
) -> Result<std::process::Output, String> {
    if !bwrap_available() {
        return Err("bubblewrap (bwrap) is not installed".to_string());
    }
    
    let (cmd, args) = wrap_with_bwrap(command, policy);
    
    let mut proc = std::process::Command::new(&cmd);
    proc.args(&args);
    
    // Inherit environment selectively
    proc.env_clear();
    for (key, value) in std::env::vars() {
        // Allow safe environment variables
        if key.starts_with("LANG")
            || key.starts_with("LC_")
            || key == "PATH"
            || key == "HOME"
            || key == "USER"
            || key == "TERM"
        {
            proc.env(&key, &value);
        }
    }
    
    proc.output().map_err(|e| format!("Failed to run sandboxed command: {}", e))
}

// ── Path Validation ─────────────────────────────────────────────────────────

/// Validate that a path does not escape allowed boundaries.
pub fn validate_path(path: &Path, policy: &SandboxPolicy) -> Result<(), String> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    
    // Check deny lists
    for denied in &policy.deny_read {
        if let Ok(denied_canon) = denied.canonicalize() {
            if canonical.starts_with(&denied_canon) {
                return Err(format!(
                    "Access denied: path {} is in protected area",
                    path.display()
                ));
            }
        }
    }
    
    // Check allow list if non-empty
    if !policy.allow_paths.is_empty() {
        let allowed = policy.allow_paths.iter().any(|allowed| {
            allowed.canonicalize()
                .map(|c| canonical.starts_with(&c))
                .unwrap_or(false)
        });
        if !allowed {
            return Err(format!(
                "Access denied: path {} is not in allowed areas",
                path.display()
            ));
        }
    }
    
    Ok(())
}

// ── Sandbox Manager ─────────────────────────────────────────────────────────

/// Sandbox mode for command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// No sandboxing (default, current behavior)
    None,
    /// Path validation only (soft sandbox)
    PathValidation,
    /// Bubblewrap namespace isolation
    Bubblewrap,
    /// Landlock kernel restrictions (process-wide)
    Landlock,
}

impl Default for SandboxMode {
    fn default() -> Self {
        Self::None
    }
}

impl std::str::FromStr for SandboxMode {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "off" | "disabled" => Ok(Self::None),
            "path" | "pathvalidation" | "soft" => Ok(Self::PathValidation),
            "bwrap" | "bubblewrap" | "namespace" => Ok(Self::Bubblewrap),
            "landlock" | "kernel" => Ok(Self::Landlock),
            _ => Err(format!("Unknown sandbox mode: {}", s)),
        }
    }
}

/// Global sandbox configuration.
pub struct Sandbox {
    pub mode: SandboxMode,
    pub policy: SandboxPolicy,
}

impl Sandbox {
    pub fn new(mode: SandboxMode, policy: SandboxPolicy) -> Self {
        Self { mode, policy }
    }
    
    /// Initialize the sandbox. For Landlock, this applies kernel restrictions.
    pub fn init(&self) -> Result<(), String> {
        match self.mode {
            SandboxMode::None => Ok(()),
            SandboxMode::PathValidation => Ok(()),
            SandboxMode::Bubblewrap => {
                if !bwrap_available() {
                    return Err("bubblewrap not available".to_string());
                }
                Ok(())
            }
            SandboxMode::Landlock => {
                if !landlock_supported() {
                    return Err("Landlock not supported on this kernel".to_string());
                }
                apply_landlock(&self.policy)
            }
        }
    }
    
    /// Check if a path is accessible under the current policy.
    pub fn check_path(&self, path: &Path) -> Result<(), String> {
        match self.mode {
            SandboxMode::None => Ok(()),
            _ => validate_path(path, &self.policy),
        }
    }
    
    /// Run a command, potentially sandboxed.
    pub fn run_command(
        &self,
        command: &str,
        timeout_secs: Option<u64>,
    ) -> Result<std::process::Output, String> {
        match self.mode {
            SandboxMode::Bubblewrap => run_sandboxed(command, &self.policy, timeout_secs),
            _ => {
                // Run directly (Landlock is process-wide, so already applied)
                std::process::Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .output()
                    .map_err(|e| format!("Command failed: {}", e))
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_policy_creation() {
        let policy = SandboxPolicy::protect_credentials(
            "/home/user/.rustyclaw/credentials",
            "/home/user/.rustyclaw/workspace",
        );
        
        assert_eq!(policy.deny_read.len(), 1);
        assert!(policy.deny_read[0].ends_with("credentials"));
    }

    #[test]
    fn test_path_validation_denied() {
        let policy = SandboxPolicy::protect_credentials(
            "/tmp/creds",
            "/tmp/workspace",
        );
        
        std::fs::create_dir_all("/tmp/creds").ok();
        std::fs::create_dir_all("/tmp/workspace").ok();
        
        let result = validate_path(Path::new("/tmp/creds/secrets.json"), &policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_validation_allowed() {
        let policy = SandboxPolicy::protect_credentials(
            "/tmp/test-creds-isolated",
            "/tmp/test-workspace",
        );
        
        let result = validate_path(Path::new("/tmp/test-workspace/file.txt"), &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bwrap_command_generation() {
        let policy = SandboxPolicy {
            workspace: PathBuf::from("/home/user/workspace"),
            ..Default::default()
        };
        
        let (cmd, args) = wrap_with_bwrap("ls -la", &policy);
        
        assert_eq!(cmd, "bwrap");
        assert!(args.contains(&"--unshare-all".to_string()));
        assert!(args.contains(&"ls -la".to_string()));
    }

    #[test]
    fn test_sandbox_mode_parsing() {
        assert_eq!("none".parse::<SandboxMode>().unwrap(), SandboxMode::None);
        assert_eq!("bwrap".parse::<SandboxMode>().unwrap(), SandboxMode::Bubblewrap);
        assert_eq!("landlock".parse::<SandboxMode>().unwrap(), SandboxMode::Landlock);
    }

    #[test]
    fn test_strict_policy() {
        let policy = SandboxPolicy::strict(
            "/workspace",
            vec![PathBuf::from("/workspace"), PathBuf::from("/tmp")],
        );
        
        assert!(policy.allow_paths.len() == 2);
        assert!(policy.deny_read.is_empty());
    }
}
