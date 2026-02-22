// ── RustyClaw TUI Client ────────────────────────────────────────────────────
//
// Terminal UI client for RustyClaw. This crate provides the interactive
// terminal interface including chat display, tool approval dialogs,
// onboarding wizard, and all TUI-specific rendering.
//
// Depends on `rustyclaw-core` for all shared logic.

pub mod action;
pub mod app;
pub mod dialogs;
pub mod gateway_client;
pub mod onboard;
pub mod pages;
pub mod panes;
pub mod tui;
pub mod tui_palette;
