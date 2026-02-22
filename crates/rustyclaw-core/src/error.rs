//! Error handling utilities for RustyClaw.
//!
//! ## Error handling patterns
//!
//! RustyClaw uses two error handling strategies:
//!
//! 1. **Tools** (`Result<String, String>`): Tools return simple string errors
//!    because these are sent back to the AI model. The error message is displayed
//!    to the model which can then try to recover or report the issue to the user.
//!
//! 2. **Application logic** (`anyhow::Result`): Internal application code uses
//!    `anyhow` for its rich error context and easy propagation.
//!
//! ## Converting between error types
//!
//! Use the `anyhow_to_tool_err` and `tool_err_to_anyhow` functions to convert
//! between the two error types when needed.

use anyhow::Result as AnyhowResult;

/// Convert an anyhow error to a tool error (string message).
pub fn anyhow_to_tool_err(err: anyhow::Error) -> String {
    err.to_string()
}

/// Convert an anyhow result to a tool result.
pub fn anyhow_to_tool_result<T>(result: AnyhowResult<T>) -> Result<T, String> {
    result.map_err(anyhow_to_tool_err)
}

/// Convert a tool error to an anyhow error.
pub fn tool_err_to_anyhow(err: String) -> anyhow::Error {
    anyhow::anyhow!(err)
}

/// Convert a tool result to an anyhow result.
pub fn tool_to_anyhow_result<T>(result: Result<T, String>) -> AnyhowResult<T> {
    result.map_err(tool_err_to_anyhow)
}
