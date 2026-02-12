use crate::config::Config;
use crate::providers;
use crate::secrets::SecretsManager;
use crate::skills::SkillManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAction {
    None,
    ClearMessages,
    Quit,
    /// Start (connect) the gateway
    GatewayStart,
    /// Stop (disconnect) the gateway
    GatewayStop,
    /// Restart the gateway connection
    GatewayRestart,
    /// Show gateway status info (no subcommand given)
    GatewayInfo,
    /// Change the active provider
    SetProvider(String),
    /// Change the active model
    SetModel(String),
    /// Show skills dialog
    ShowSkills,
    /// Show the secrets dialog
    ShowSecrets,
    /// Show the provider selector dialog
    ShowProviderSelector,
}

#[derive(Debug, Clone)]
pub struct CommandResponse {
    pub messages: Vec<String>,
    pub action: CommandAction,
}

pub struct CommandContext<'a> {
    pub secrets_manager: &'a mut SecretsManager,
    pub skill_manager: &'a mut SkillManager,
    pub config: &'a mut Config,
}

/// List of all known command names (without the / prefix).
/// Includes subcommand forms so tab-completion works for them.
pub fn command_names() -> Vec<String> {
    let mut names: Vec<String> = vec![
        "help".into(),
        "clear".into(),
        "enable-access".into(),
        "disable-access".into(),
        "onboard".into(),
        "reload-skills".into(),
        "gateway".into(),
        "gateway start".into(),
        "gateway stop".into(),
        "gateway restart".into(),
        "provider".into(),
        "model".into(),
        "skills".into(),
        "secrets".into(),
        "quit".into(),
    ];
    for p in providers::provider_ids() {
        names.push(format!("provider {}", p));
    }
    for m in providers::all_model_names() {
        names.push(format!("model {}", m));
    }
    names
}

pub fn handle_command(input: &str, context: &mut CommandContext<'_>) -> CommandResponse {
    // Strip the leading '/' if present
    let trimmed = input.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return CommandResponse {
            messages: Vec::new(),
            action: CommandAction::None,
        };
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.is_empty() {
        return CommandResponse {
            messages: Vec::new(),
            action: CommandAction::None,
        };
    }

    match parts[0] {
        "help" => CommandResponse {
            messages: vec![
                "Available commands:".to_string(),
                "  /help                    - Show this help".to_string(),
                "  /clear                   - Clear messages and conversation memory".to_string(),
                "  /enable-access           - Enable agent access to secrets".to_string(),
                "  /disable-access          - Disable agent access to secrets".to_string(),
                "  /onboard                 - Run setup wizard (use CLI: rustyclaw onboard)".to_string(),
                "  /reload-skills           - Reload skills".to_string(),
                "  /gateway                 - Show gateway connection status".to_string(),
                "  /gateway start           - Connect to the gateway".to_string(),
                "  /gateway stop            - Disconnect from the gateway".to_string(),
                "  /gateway restart         - Restart the gateway connection".to_string(),
                "  /provider <name>         - Change the AI provider".to_string(),
                "  /model <name>            - Change the AI model".to_string(),
                "  /skills                  - Show loaded skills".to_string(),
                "  /secrets                 - Open the secrets vault".to_string(),
            ],
            action: CommandAction::None,
        },
        "clear" => CommandResponse {
            messages: vec!["Messages and conversation memory cleared.".to_string()],
            action: CommandAction::ClearMessages,
        },
        "enable-access" => {
            context.secrets_manager.set_agent_access(true);
            context.config.agent_access = true;
            let _ = context.config.save(None);
            CommandResponse {
                messages: vec!["Agent access to secrets enabled.".to_string()],
                action: CommandAction::None,
            }
        }
        "disable-access" => {
            context.secrets_manager.set_agent_access(false);
            context.config.agent_access = false;
            let _ = context.config.save(None);
            CommandResponse {
                messages: vec!["Agent access to secrets disabled.".to_string()],
                action: CommandAction::None,
            }
        }
        "reload-skills" => match context.skill_manager.load_skills() {
            Ok(_) => CommandResponse {
                messages: vec![format!(
                    "Reloaded {} skills.",
                    context.skill_manager.get_skills().len()
                )],
                action: CommandAction::None,
            },
            Err(err) => CommandResponse {
                messages: vec![format!("Error reloading skills: {}", err)],
                action: CommandAction::None,
            },
        },
        "onboard" => CommandResponse {
            messages: vec![
                "The onboard wizard is an interactive CLI command.".to_string(),
                "Run it from your terminal:  rustyclaw onboard".to_string(),
            ],
            action: CommandAction::None,
        },
        "gateway" => match parts.get(1).copied() {
            Some("start") => CommandResponse {
                messages: vec!["Starting gateway connection…".to_string()],
                action: CommandAction::GatewayStart,
            },
            Some("stop") => CommandResponse {
                messages: vec!["Stopping gateway connection…".to_string()],
                action: CommandAction::GatewayStop,
            },
            Some("restart") => CommandResponse {
                messages: vec!["Restarting gateway connection…".to_string()],
                action: CommandAction::GatewayRestart,
            },
            Some(sub) => CommandResponse {
                messages: vec![
                    format!("Unknown gateway subcommand: {}", sub),
                    "Usage: /gateway start|stop|restart".to_string(),
                ],
                action: CommandAction::None,
            },
            None => CommandResponse {
                messages: Vec::new(),
                action: CommandAction::GatewayInfo,
            },
        },
        "skills" => CommandResponse {
            messages: Vec::new(),
            action: CommandAction::ShowSkills,
        },
        "secrets" => CommandResponse {
            messages: Vec::new(),
            action: CommandAction::ShowSecrets,
        },
        "provider" => match parts.get(1) {
            Some(name) => {
                let name = name.to_string();
                CommandResponse {
                    messages: vec![format!("Switching provider to {}…", name)],
                    action: CommandAction::SetProvider(name),
                }
            }
            None => {
                CommandResponse {
                    messages: Vec::new(),
                    action: CommandAction::ShowProviderSelector,
                }
            }
        },
        "model" => match parts.get(1) {
            Some(name) => {
                let name = name.to_string();
                CommandResponse {
                    messages: vec![format!("Switching model to {}…", name)],
                    action: CommandAction::SetModel(name),
                }
            }
            None => {
                let list = providers::all_model_names().join(", ");
                CommandResponse {
                    messages: vec![
                        "Usage: /model <name>".to_string(),
                        format!("Known models: {}", list),
                    ],
                    action: CommandAction::None,
                }
            }
        },
        "q" | "quit" | "exit" => CommandResponse {
            messages: Vec::new(),
            action: CommandAction::Quit,
        },
        _ => CommandResponse {
            messages: vec![
                format!("Unknown command: /{}", parts[0]),
                "Type /help for available commands".to_string(),
            ],
            action: CommandAction::None,
        },
    }
}
