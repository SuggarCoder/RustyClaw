use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Represents a skill that can be loaded and executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub name: String,
    pub description: Option<String>,
    pub path: PathBuf,
    pub enabled: bool,
    /// Raw instructions from SKILL.md (after frontmatter)
    #[serde(default)]
    pub instructions: String,
    /// Parsed metadata from frontmatter
    #[serde(default)]
    pub metadata: SkillMetadata,
}

/// OpenClaw-compatible skill metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillMetadata {
    /// Always include this skill (skip gating)
    #[serde(default)]
    pub always: bool,
    /// Optional emoji for UI
    pub emoji: Option<String>,
    /// Homepage URL
    pub homepage: Option<String>,
    /// Required OS platforms (darwin, linux, win32)
    #[serde(default)]
    pub os: Vec<String>,
    /// Gating requirements
    #[serde(default)]
    pub requires: SkillRequirements,
    /// Primary env var for API key
    #[serde(rename = "primaryEnv")]
    pub primary_env: Option<String>,
}

/// Skill gating requirements
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillRequirements {
    /// All these binaries must exist on PATH
    #[serde(default)]
    pub bins: Vec<String>,
    /// At least one of these binaries must exist
    #[serde(rename = "anyBins", default)]
    pub any_bins: Vec<String>,
    /// All these env vars must be set
    #[serde(default)]
    pub env: Vec<String>,
    /// All these config paths must be truthy
    #[serde(default)]
    pub config: Vec<String>,
}

/// Result of checking skill requirements
#[derive(Debug, Clone)]
pub struct GateCheckResult {
    pub passed: bool,
    pub missing_bins: Vec<String>,
    pub missing_env: Vec<String>,
    pub missing_config: Vec<String>,
    pub wrong_os: bool,
}

/// Manages skills compatible with OpenClaw
pub struct SkillManager {
    skills_dirs: Vec<PathBuf>,
    skills: Vec<Skill>,
    /// Environment variables to check against
    env_vars: HashMap<String, String>,
}

impl SkillManager {
    pub fn new(skills_dir: PathBuf) -> Self {
        Self {
            skills_dirs: vec![skills_dir],
            skills: Vec::new(),
            env_vars: std::env::vars().collect(),
        }
    }

    /// Create with multiple skill directories (for precedence)
    pub fn with_dirs(dirs: Vec<PathBuf>) -> Self {
        Self {
            skills_dirs: dirs,
            skills: Vec::new(),
            env_vars: std::env::vars().collect(),
        }
    }

    /// Load skills from all configured directories
    /// Later directories have higher precedence (override earlier ones by name)
    pub fn load_skills(&mut self) -> Result<()> {
        self.skills.clear();
        let mut seen_names: HashMap<String, usize> = HashMap::new();

        for dir in &self.skills_dirs.clone() {
            if !dir.exists() {
                continue;
            }

            // Look for skill directories containing SKILL.md
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    let skill_file = path.join("SKILL.md");
                    if skill_file.exists() {
                        if let Ok(skill) = self.load_skill_md(&skill_file) {
                            // Check if we already have this skill (override by precedence)
                            if let Some(&idx) = seen_names.get(&skill.name) {
                                self.skills[idx] = skill.clone();
                            } else {
                                seen_names.insert(skill.name.clone(), self.skills.len());
                                self.skills.push(skill);
                            }
                        }
                    }
                }

                // Also support legacy .skill/.json/.yaml files
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "skill" || ext == "json" || ext == "yaml" || ext == "yml" {
                            if let Ok(skill) = self.load_skill_legacy(&path) {
                                if let Some(&idx) = seen_names.get(&skill.name) {
                                    self.skills[idx] = skill.clone();
                                } else {
                                    seen_names.insert(skill.name.clone(), self.skills.len());
                                    self.skills.push(skill);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Load a skill from SKILL.md format (AgentSkills compatible)
    fn load_skill_md(&self, path: &Path) -> Result<Skill> {
        let content = std::fs::read_to_string(path)?;
        let (frontmatter, instructions) = parse_frontmatter(&content)?;

        // Parse frontmatter as YAML
        let name = frontmatter
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Skill missing 'name' in frontmatter"))?
            .to_string();

        let description = frontmatter
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Parse metadata if present
        let metadata = if let Some(meta_val) = frontmatter.get("metadata") {
            // metadata can be a string (JSON) or an object
            if let Some(meta_str) = meta_val.as_str() {
                serde_json::from_str(meta_str).unwrap_or_default()
            } else if let Some(openclaw) = meta_val.get("openclaw") {
                // Convert YAML Value to JSON Value via serialization round-trip
                let json_str = serde_json::to_string(&openclaw).unwrap_or_default();
                serde_json::from_str(&json_str).unwrap_or_default()
            } else {
                SkillMetadata::default()
            }
        } else {
            SkillMetadata::default()
        };

        // Replace {baseDir} placeholder in instructions
        let base_dir = path.parent().unwrap_or(Path::new("."));
        let instructions = instructions.replace("{baseDir}", &base_dir.display().to_string());

        Ok(Skill {
            name,
            description,
            path: path.to_path_buf(),
            enabled: true,
            instructions,
            metadata,
        })
    }

    /// Load a legacy skill file (.skill/.json/.yaml)
    fn load_skill_legacy(&self, path: &Path) -> Result<Skill> {
        let is_json = path.extension().is_some_and(|e| e == "json" || e == "skill");
        let is_yaml = path.extension().is_some_and(|e| e == "yaml" || e == "yml");

        if !is_json && !is_yaml {
            anyhow::bail!("Unsupported skill file format: {:?}", path);
        }

        let content = std::fs::read_to_string(path)?;

        let skill: Skill = if is_yaml {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        };

        Ok(skill)
    }

    /// Check if a skill passes its gating requirements
    pub fn check_gates(&self, skill: &Skill) -> GateCheckResult {
        let mut result = GateCheckResult {
            passed: true,
            missing_bins: Vec::new(),
            missing_env: Vec::new(),
            missing_config: Vec::new(),
            wrong_os: false,
        };

        // Always-enabled skills skip all gates
        if skill.metadata.always {
            return result;
        }

        // Check OS requirement
        if !skill.metadata.os.is_empty() {
            let current_os = if cfg!(target_os = "macos") {
                "darwin"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else if cfg!(target_os = "windows") {
                "win32"
            } else {
                "unknown"
            };

            if !skill.metadata.os.iter().any(|os| os == current_os) {
                result.wrong_os = true;
                result.passed = false;
            }
        }

        // Check required binaries
        for bin in &skill.metadata.requires.bins {
            if !self.binary_exists(bin) {
                result.missing_bins.push(bin.clone());
                result.passed = false;
            }
        }

        // Check anyBins (at least one must exist)
        if !skill.metadata.requires.any_bins.is_empty() {
            let any_found = skill
                .metadata
                .requires
                .any_bins
                .iter()
                .any(|bin| self.binary_exists(bin));
            if !any_found {
                result.missing_bins.extend(skill.metadata.requires.any_bins.clone());
                result.passed = false;
            }
        }

        // Check required env vars
        for env_var in &skill.metadata.requires.env {
            if !self.env_vars.contains_key(env_var) {
                result.missing_env.push(env_var.clone());
                result.passed = false;
            }
        }

        // Config checks would require access to config - mark as missing for now
        // In a real implementation, this would check openclaw.json
        result.missing_config = skill.metadata.requires.config.clone();
        if !result.missing_config.is_empty() {
            // Don't fail on config checks for now - they require config integration
        }

        result
    }

    /// Check if a binary exists on PATH
    fn binary_exists(&self, name: &str) -> bool {
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return true;
                }
                // On Windows, also check with .exe
                #[cfg(windows)]
                {
                    let candidate_exe = dir.join(format!("{}.exe", name));
                    if candidate_exe.exists() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get all loaded skills
    pub fn get_skills(&self) -> &[Skill] {
        &self.skills
    }

    /// Get only enabled skills that pass gating
    pub fn get_eligible_skills(&self) -> Vec<&Skill> {
        self.skills
            .iter()
            .filter(|s| s.enabled && self.check_gates(s).passed)
            .collect()
    }

    /// Get a specific skill by name
    pub fn get_skill(&self, name: &str) -> Option<&Skill> {
        self.skills.iter().find(|s| s.name == name)
    }

    /// Enable or disable a skill
    pub fn set_skill_enabled(&mut self, name: &str, enabled: bool) -> Result<()> {
        if let Some(skill) = self.skills.iter_mut().find(|s| s.name == name) {
            skill.enabled = enabled;
            Ok(())
        } else {
            anyhow::bail!("Skill not found: {}", name)
        }
    }

    /// Generate prompt context for all eligible skills
    pub fn generate_prompt_context(&self) -> String {
        let eligible = self.get_eligible_skills();
        if eligible.is_empty() {
            return String::new();
        }

        let mut context = String::from("## Available Skills\n\n");
        context.push_str("The following skills provide specialized instructions for specific tasks.\n");
        context.push_str("Use the read tool to load a skill's file when the task matches its description.\n\n");
        context.push_str("<available_skills>\n");

        for skill in eligible {
            context.push_str("  <skill>\n");
            context.push_str(&format!("    <name>{}</name>\n", skill.name));
            if let Some(ref desc) = skill.description {
                context.push_str(&format!("    <description>{}</description>\n", desc));
            }
            context.push_str(&format!("    <location>{}</location>\n", skill.path.display()));
            context.push_str("  </skill>\n");
        }

        context.push_str("</available_skills>\n");
        context
    }

    /// Get full instructions for a skill (for when agent reads SKILL.md)
    pub fn get_skill_instructions(&self, name: &str) -> Option<String> {
        self.get_skill(name).map(|s| s.instructions.clone())
    }
}

/// Parse YAML frontmatter from a markdown file
fn parse_frontmatter(content: &str) -> Result<(serde_yaml::Value, String)> {
    let content = content.trim_start();
    
    if !content.starts_with("---") {
        // No frontmatter, treat entire content as instructions
        return Ok((serde_yaml::Value::Mapping(Default::default()), content.to_string()));
    }

    // Find the closing ---
    let after_first = &content[3..];
    if let Some(end_idx) = after_first.find("\n---") {
        let frontmatter_str = &after_first[..end_idx];
        let instructions = after_first[end_idx + 4..].trim_start().to_string();
        
        let frontmatter: serde_yaml::Value = serde_yaml::from_str(frontmatter_str)
            .context("Failed to parse YAML frontmatter")?;
        
        Ok((frontmatter, instructions))
    } else {
        // No closing ---, treat as no frontmatter
        Ok((serde_yaml::Value::Mapping(Default::default()), content.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_manager_creation() {
        let temp_dir = std::env::temp_dir().join("rustyclaw_test_skills");
        let manager = SkillManager::new(temp_dir);
        assert_eq!(manager.get_skills().len(), 0);
    }

    #[test]
    fn test_parse_frontmatter_with_yaml() {
        let content = r#"---
name: test-skill
description: A test skill
---

# Instructions

Do the thing.
"#;
        let (fm, instructions) = parse_frontmatter(content).unwrap();
        assert_eq!(fm["name"].as_str(), Some("test-skill"));
        assert_eq!(fm["description"].as_str(), Some("A test skill"));
        assert!(instructions.contains("Do the thing"));
    }

    #[test]
    fn test_parse_frontmatter_without_yaml() {
        let content = "# Just some markdown\n\nNo frontmatter here.";
        let (fm, instructions) = parse_frontmatter(content).unwrap();
        assert!(fm.is_mapping());
        assert!(instructions.contains("Just some markdown"));
    }

    #[test]
    fn test_binary_exists() {
        let manager = SkillManager::new(std::env::temp_dir());
        // 'ls' or 'dir' should exist on most systems
        #[cfg(unix)]
        assert!(manager.binary_exists("ls"));
        #[cfg(windows)]
        assert!(manager.binary_exists("cmd"));
    }

    #[test]
    fn test_gate_check_always() {
        let manager = SkillManager::new(std::env::temp_dir());
        let skill = Skill {
            name: "test".into(),
            description: None,
            path: PathBuf::new(),
            enabled: true,
            instructions: String::new(),
            metadata: SkillMetadata {
                always: true,
                ..Default::default()
            },
        };
        let result = manager.check_gates(&skill);
        assert!(result.passed);
    }

    #[test]
    fn test_gate_check_missing_bin() {
        let manager = SkillManager::new(std::env::temp_dir());
        let skill = Skill {
            name: "test".into(),
            description: None,
            path: PathBuf::new(),
            enabled: true,
            instructions: String::new(),
            metadata: SkillMetadata {
                requires: SkillRequirements {
                    bins: vec!["nonexistent_binary_12345".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let result = manager.check_gates(&skill);
        assert!(!result.passed);
        assert!(result.missing_bins.contains(&"nonexistent_binary_12345".to_string()));
    }

    #[test]
    fn test_generate_prompt_context() {
        let mut manager = SkillManager::new(std::env::temp_dir());
        manager.skills.push(Skill {
            name: "test-skill".into(),
            description: Some("Does testing".into()),
            path: PathBuf::from("/skills/test/SKILL.md"),
            enabled: true,
            instructions: "Test instructions".into(),
            metadata: SkillMetadata::default(),
        });
        let context = manager.generate_prompt_context();
        assert!(context.contains("test-skill"));
        assert!(context.contains("Does testing"));
        assert!(context.contains("<available_skills>"));
    }
}
