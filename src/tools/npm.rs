// npm / Node.js package management tool for RustyClaw.
//
// Provides a unified interface for installing Node.js/npm, managing
// packages, running scripts, and building projects.  Supports npm,
// npx, and basic nvm/fnm for Node version management.

use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

// ── Helpers ─────────────────────────────────────────────────────────────────

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
    if !stderr.is_empty() && !stdout.is_empty() {
        Ok(format!("{}\n[stderr] {}", stdout, stderr))
    } else if !stdout.is_empty() {
        Ok(stdout)
    } else {
        Ok(stderr)
    }
}

fn sh_in(dir: &Path, script: &str) -> Result<String, String> {
    // Source nvm/fnm if available so `node`/`npm` resolve inside subshells.
    let preamble = r#"
        export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
        [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" 2>/dev/null
        command -v fnm >/dev/null 2>&1 && eval "$(fnm env --use-on-cd)" 2>/dev/null
    "#;
    let full = format!("{}\n{}", preamble.trim(), script);

    let output = Command::new("sh")
        .arg("-c")
        .arg(&full)
        .current_dir(dir)
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
    if !stderr.is_empty() && !stdout.is_empty() {
        Ok(format!("{}\n[stderr] {}", stdout, stderr))
    } else if !stdout.is_empty() {
        Ok(stdout)
    } else {
        Ok(stderr)
    }
}

fn is_node_installed(workspace_dir: &Path) -> bool {
    sh_in(workspace_dir, "command -v node >/dev/null 2>&1 && echo yes")
        .map(|s| s.contains("yes"))
        .unwrap_or(false)
}

fn is_npm_installed(workspace_dir: &Path) -> bool {
    sh_in(workspace_dir, "command -v npm >/dev/null 2>&1 && echo yes")
        .map(|s| s.contains("yes"))
        .unwrap_or(false)
}

// ── Tool executor ───────────────────────────────────────────────────────────

/// `npm_manage` — unified Node.js / npm administration tool.
pub fn exec_npm_manage(args: &Value, workspace_dir: &Path) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or("Missing required parameter: action")?;

    match action {
        // ── setup / install node+npm ────────────────────────────
        "setup" | "install-node" => {
            if is_node_installed(workspace_dir) && is_npm_installed(workspace_dir) {
                let node_v = sh_in(workspace_dir, "node --version 2>&1")
                    .unwrap_or_else(|_| "unknown".into());
                let npm_v = sh_in(workspace_dir, "npm --version 2>&1")
                    .unwrap_or_else(|_| "unknown".into());
                return Ok(format!(
                    "Node.js ({}) and npm ({}) are already installed.",
                    node_v.trim(),
                    npm_v.trim(),
                ));
            }
            let os = std::env::consts::OS;
            match os {
                "macos" => {
                    // Try brew first, then the official installer script
                    let result = sh("command -v brew >/dev/null 2>&1 && brew install node 2>&1");
                    if result.is_ok() {
                        return result;
                    }
                    sh("curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash 2>&1 && \
                        export NVM_DIR=\"$HOME/.nvm\" && . \"$NVM_DIR/nvm.sh\" && \
                        nvm install --lts 2>&1")
                }
                "linux" => {
                    sh("curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash 2>&1 && \
                        export NVM_DIR=\"$HOME/.nvm\" && . \"$NVM_DIR/nvm.sh\" && \
                        nvm install --lts 2>&1")
                }
                _ => Err(format!("Unsupported OS for automatic Node.js install: {}", os)),
            }
        }

        // ── version ─────────────────────────────────────────────
        "version" | "versions" => {
            let node_v = sh_in(workspace_dir, "node --version 2>&1")
                .unwrap_or_else(|_| "not installed".into());
            let npm_v = sh_in(workspace_dir, "npm --version 2>&1")
                .unwrap_or_else(|_| "not installed".into());
            let npx_v = sh_in(workspace_dir, "npx --version 2>&1")
                .unwrap_or_else(|_| "not installed".into());
            Ok(format!(
                "node: {}\nnpm:  {}\nnpx:  {}",
                node_v.trim(),
                npm_v.trim(),
                npx_v.trim(),
            ))
        }

        // ── init (create package.json) ──────────────────────────
        "init" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed. Run with action 'setup' first.".into());
            }
            let yes = args.get("yes").and_then(|v| v.as_bool()).unwrap_or(true);
            let cmd = if yes { "npm init -y 2>&1" } else { "npm init 2>&1" };
            sh_in(workspace_dir, cmd)
        }

        // ── install (npm install) ───────────────────────────────
        "npm-install" | "add" | "i" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            // Accept single package, array, or no packages (install from package.json)
            let packages: Vec<String> =
                if let Some(pkg) = args.get("package").and_then(|v| v.as_str()) {
                    vec![pkg.to_string()]
                } else if let Some(pkgs) = args.get("packages").and_then(|v| v.as_array()) {
                    pkgs.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                } else {
                    vec![]
                };

            let mut cmd = String::from("npm install");
            if !packages.is_empty() {
                cmd.push(' ');
                cmd.push_str(&packages.join(" "));
            }
            // --save-dev flag
            if args
                .get("dev")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                cmd.push_str(" --save-dev");
            }
            // --global flag
            if args
                .get("global")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                cmd.push_str(" -g");
            }
            cmd.push_str(" 2>&1");
            sh_in(workspace_dir, &cmd)
        }

        // ── uninstall ───────────────────────────────────────────
        "uninstall" | "remove" | "rm" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let packages: Vec<String> =
                if let Some(pkg) = args.get("package").and_then(|v| v.as_str()) {
                    vec![pkg.to_string()]
                } else if let Some(pkgs) = args.get("packages").and_then(|v| v.as_array()) {
                    pkgs.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                } else {
                    return Err("Missing required parameter: package or packages.".into());
                };
            if packages.is_empty() {
                return Err("No packages specified.".into());
            }
            let global_flag = if args
                .get("global")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                " -g"
            } else {
                ""
            };
            sh_in(
                workspace_dir,
                &format!("npm uninstall {}{} 2>&1", packages.join(" "), global_flag),
            )
        }

        // ── list ────────────────────────────────────────────────
        "list" | "ls" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let depth = args
                .get("depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let global_flag = if args
                .get("global")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                " -g"
            } else {
                ""
            };
            sh_in(
                workspace_dir,
                &format!("npm list --depth={}{} 2>&1", depth, global_flag),
            )
        }

        // ── outdated ────────────────────────────────────────────
        "outdated" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            // npm outdated returns exit 1 when packages are outdated, so
            // we append `|| true` to avoid treating it as an error.
            sh_in(workspace_dir, "npm outdated 2>&1 || true")
        }

        // ── update ──────────────────────────────────────────────
        "update" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let pkg = args.get("package").and_then(|v| v.as_str());
            let cmd = match pkg {
                Some(p) => format!("npm update {} 2>&1", p),
                None => "npm update 2>&1".to_string(),
            };
            sh_in(workspace_dir, &cmd)
        }

        // ── run (npm run <script>) ──────────────────────────────
        "run" | "run-script" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let script = args
                .get("script")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: script (e.g. 'build', 'dev', 'start')")?;
            let extra = args.get("args").and_then(|v| v.as_str()).unwrap_or("");
            let cmd = if extra.is_empty() {
                format!("npm run {} 2>&1", script)
            } else {
                format!("npm run {} -- {} 2>&1", script, extra)
            };
            sh_in(workspace_dir, &cmd)
        }

        // ── start ───────────────────────────────────────────────
        "start" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            sh_in(workspace_dir, "npm start 2>&1")
        }

        // ── build ───────────────────────────────────────────────
        "build" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            sh_in(workspace_dir, "npm run build 2>&1")
        }

        // ── test ────────────────────────────────────────────────
        "test" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            sh_in(workspace_dir, "npm test 2>&1")
        }

        // ── npx (run a package binary) ──────────────────────────
        "npx" | "exec" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: command (e.g. 'create-react-app my-app')")?;
            sh_in(workspace_dir, &format!("npx -y {} 2>&1", command))
        }

        // ── audit ───────────────────────────────────────────────
        "audit" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let fix = args
                .get("fix")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let cmd = if fix {
                "npm audit fix 2>&1"
            } else {
                "npm audit 2>&1 || true"
            };
            sh_in(workspace_dir, cmd)
        }

        // ── cache clean ─────────────────────────────────────────
        "cache-clean" | "cache" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            sh_in(workspace_dir, "npm cache clean --force 2>&1")
        }

        // ── info (show package info) ────────────────────────────
        "info" | "view" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let pkg = args
                .get("package")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: package")?;
            sh_in(workspace_dir, &format!("npm info {} 2>&1", pkg))
        }

        // ── search ──────────────────────────────────────────────
        "search" => {
            if !is_npm_installed(workspace_dir) {
                return Err("npm is not installed.".into());
            }
            let query = args
                .get("query")
                .and_then(|v| v.as_str())
                .ok_or("Missing required parameter: query")?;
            sh_in(workspace_dir, &format!("npm search {} 2>&1", query))
        }

        // ── status (overview) ───────────────────────────────────
        "status" => {
            let node_installed = is_node_installed(workspace_dir);
            let npm_installed = is_npm_installed(workspace_dir);
            let node_v = if node_installed {
                sh_in(workspace_dir, "node --version 2>&1")
                    .unwrap_or_else(|_| "unknown".into())
            } else {
                "not installed".into()
            };
            let npm_v = if npm_installed {
                sh_in(workspace_dir, "npm --version 2>&1")
                    .unwrap_or_else(|_| "unknown".into())
            } else {
                "not installed".into()
            };

            // Check for package.json
            let has_pkg_json = workspace_dir.join("package.json").exists();
            let has_node_modules = workspace_dir.join("node_modules").exists();
            let has_lock = workspace_dir.join("package-lock.json").exists()
                || workspace_dir.join("yarn.lock").exists()
                || workspace_dir.join("pnpm-lock.yaml").exists();

            // Read scripts from package.json if it exists
            let scripts = if has_pkg_json {
                match std::fs::read_to_string(workspace_dir.join("package.json")) {
                    Ok(content) => {
                        if let Ok(pkg) = serde_json::from_str::<Value>(&content) {
                            if let Some(s) = pkg.get("scripts").and_then(|s| s.as_object()) {
                                s.keys().cloned().collect::<Vec<_>>().join(", ")
                            } else {
                                "none".into()
                            }
                        } else {
                            "parse error".into()
                        }
                    }
                    Err(_) => "read error".into(),
                }
            } else {
                "n/a".into()
            };

            Ok(json!({
                "node": node_v.trim(),
                "npm": npm_v.trim(),
                "package_json": has_pkg_json,
                "node_modules": has_node_modules,
                "lock_file": has_lock,
                "scripts": scripts,
            })
            .to_string())
        }

        _ => Err(format!(
            "Unknown npm action: '{}'. Valid actions: setup, version, init, \
             npm-install, uninstall, list, outdated, update, run, start, build, \
             test, npx, audit, cache-clean, info, search, status.",
            action
        )),
    }
}
