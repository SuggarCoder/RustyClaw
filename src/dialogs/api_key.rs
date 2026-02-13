//! API key input dialog.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::action::Action;
use crate::panes::DisplayMessage;
use crate::providers;
use crate::secrets::SecretsManager;
use crate::theme::tui_palette as tp;

/// Phase of the API-key dialog overlay.
#[derive(Debug, Clone, PartialEq)]
pub enum ApiKeyDialogPhase {
    /// Prompting the user to enter an API key (text is masked)
    EnterKey,
    /// Asking whether to store the entered key permanently
    ConfirmStore,
}

/// State for the API-key input dialog overlay.
pub struct ApiKeyDialogState {
    /// Which provider this key is for
    pub provider: String,
    /// Display name for the provider
    pub display: String,
    /// Name of the secret key (e.g. "ANTHROPIC_API_KEY")
    #[allow(dead_code)]
    pub secret_key: String,
    /// Current input buffer (the API key being typed)
    pub input: String,
    /// Which phase the dialog is in
    pub phase: ApiKeyDialogPhase,
}

/// Open the API-key input dialog for the given provider.
pub fn open_api_key_dialog(
    provider: &str,
    messages: &mut Vec<DisplayMessage>,
) -> Option<ApiKeyDialogState> {
    let secret_key = match providers::secret_key_for_provider(provider) {
        Some(k) => k.to_string(),
        None => return None, // shouldn't happen, but just in case
    };
    let display = providers::display_name_for_provider(provider).to_string();
    messages.push(DisplayMessage::warning(format!(
        "No API key found for {}. Please enter one below.",
        display,
    )));
    Some(ApiKeyDialogState {
        provider: provider.to_string(),
        display,
        secret_key,
        input: String::new(),
        phase: ApiKeyDialogPhase::EnterKey,
    })
}

/// Handle key events when the API key dialog is open.
/// Returns (updated dialog state or None if closed, action to dispatch).
pub fn handle_api_key_dialog_key(
    dialog: ApiKeyDialogState,
    code: crossterm::event::KeyCode,
    messages: &mut Vec<DisplayMessage>,
) -> (Option<ApiKeyDialogState>, Action) {
    use crossterm::event::KeyCode;

    let mut dialog = dialog;

    match dialog.phase {
        ApiKeyDialogPhase::EnterKey => match code {
            KeyCode::Esc => {
                messages.push(DisplayMessage::info("API key entry cancelled."));
                (None, Action::Noop)
            }
            KeyCode::Enter => {
                if dialog.input.is_empty() {
                    messages.push(DisplayMessage::info(
                        "No key entered — you can add one later with /provider.",
                    ));
                    (None, Action::Noop)
                } else {
                    // Move to confirmation phase
                    dialog.phase = ApiKeyDialogPhase::ConfirmStore;
                    (Some(dialog), Action::Noop)
                }
            }
            KeyCode::Backspace => {
                dialog.input.pop();
                (Some(dialog), Action::Noop)
            }
            KeyCode::Char(c) => {
                dialog.input.push(c);
                (Some(dialog), Action::Noop)
            }
            _ => (Some(dialog), Action::Noop),
        },
        ApiKeyDialogPhase::ConfirmStore => match code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                // Store it
                let provider = dialog.provider.clone();
                let key = dialog.input.clone();
                (None, Action::ConfirmStoreSecret { provider, key })
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                // Use the key for this session but don't store
                messages.push(DisplayMessage::success(format!(
                    "✓ API key for {} set for this session (not stored).",
                    dialog.display,
                )));
                // Proceed to model selection
                (None, Action::FetchModels(dialog.provider.clone()))
            }
            _ => (Some(dialog), Action::Noop),
        },
    }
}

/// Store the API key in the secrets vault after user confirmation.
pub fn handle_confirm_store_secret(
    provider: &str,
    key: &str,
    secrets_manager: &mut SecretsManager,
    messages: &mut Vec<DisplayMessage>,
) -> Option<Action> {
    let secret_key = providers::secret_key_for_provider(provider).unwrap_or("API_KEY");
    let display = providers::display_name_for_provider(provider).to_string();

    match secrets_manager.store_secret(secret_key, key) {
        Ok(()) => {
            messages.push(DisplayMessage::success(format!(
                "✓ API key for {} stored securely.",
                display,
            )));
        }
        Err(e) => {
            messages.push(DisplayMessage::error(format!(
                "Failed to store API key: {}. Key is set for this session only.",
                e,
            )));
        }
    }
    // After storing the key, proceed to model selection
    Some(Action::FetchModels(provider.to_string()))
}

/// Draw a centered API-key dialog overlay.
pub fn draw_api_key_dialog(frame: &mut ratatui::Frame<'_>, area: Rect, dialog: &ApiKeyDialogState) {
    let dialog_w = 56.min(area.width.saturating_sub(4));
    let dialog_h = 7_u16.min(area.height.saturating_sub(4)).max(5);
    let x = area.x + (area.width.saturating_sub(dialog_w)) / 2;
    let y = area.y + (area.height.saturating_sub(dialog_h)) / 2;
    let dialog_area = Rect::new(x, y, dialog_w, dialog_h);

    // Clear the background behind the dialog
    frame.render_widget(Clear, dialog_area);

    let title = format!(" {} API Key ", dialog.display);
    let block = Block::default()
        .title(Span::styled(&title, tp::title_focused()))
        .title_bottom(
            Line::from(Span::styled(
                " Esc to cancel ",
                Style::default().fg(tp::MUTED),
            ))
            .right_aligned(),
        )
        .borders(Borders::ALL)
        .border_style(tp::focused_border())
        .border_type(ratatui::widgets::BorderType::Rounded);

    let inner = block.inner(dialog_area);
    frame.render_widget(block, dialog_area);

    match dialog.phase {
        ApiKeyDialogPhase::EnterKey => {
            // Label
            let label = Line::from(Span::styled(
                format!(" Enter your {} API key:", dialog.display),
                Style::default().fg(tp::TEXT),
            ));
            if inner.height >= 1 {
                frame.render_widget(
                    Paragraph::new(label),
                    Rect::new(inner.x, inner.y, inner.width, 1),
                );
            }

            // Masked input
            if inner.height >= 3 {
                let masked: String = "•".repeat(dialog.input.len());
                let input_area =
                    Rect::new(inner.x + 1, inner.y + 2, inner.width.saturating_sub(2), 1);
                let prompt = Line::from(vec![
                    Span::styled("❯ ", Style::default().fg(tp::ACCENT)),
                    Span::styled(&masked, Style::default().fg(tp::TEXT)),
                ]);
                frame.render_widget(Paragraph::new(prompt), input_area);

                // Show cursor
                frame.set_cursor_position((input_area.x + 2 + masked.len() as u16, input_area.y));
            }
        }
        ApiKeyDialogPhase::ConfirmStore => {
            // Show key length hint
            let hint = Line::from(Span::styled(
                format!(" Key entered ({} chars).", dialog.input.len()),
                Style::default().fg(tp::SUCCESS),
            ));
            if inner.height >= 1 {
                frame.render_widget(
                    Paragraph::new(hint),
                    Rect::new(inner.x, inner.y, inner.width, 1),
                );
            }

            // Store question
            if inner.height >= 3 {
                let question = Line::from(vec![
                    Span::styled(
                        " Store permanently in secrets vault? ",
                        Style::default().fg(tp::TEXT),
                    ),
                    Span::styled(
                        "[Y/n]",
                        Style::default()
                            .fg(tp::ACCENT_BRIGHT)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]);
                frame.render_widget(
                    Paragraph::new(question),
                    Rect::new(inner.x, inner.y + 2, inner.width, 1),
                );
            }
        }
    }
}
