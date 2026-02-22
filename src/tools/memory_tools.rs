//! Memory tools: memory_search and memory_get.

use serde_json::Value;
use std::path::Path;
use tracing::{debug, instrument};

/// Default half-life for temporal decay in days.
const DEFAULT_HALF_LIFE_DAYS: f64 = 30.0;

/// Search memory files for relevant content.
///
/// Supports optional recency boosting via temporal decay. Recent memory files
/// are weighted higher using exponential decay with a configurable half-life.
#[instrument(skip(args, workspace_dir), fields(query))]
pub fn exec_memory_search(args: &Value, workspace_dir: &Path) -> Result<String, String> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: query".to_string())?;

    tracing::Span::current().record("query", query);

    let max_results = args
        .get("maxResults")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as usize;

    let min_score = args
        .get("minScore")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.1);

    // Recency boost options
    let use_recency = args
        .get("recencyBoost")
        .and_then(|v| v.as_bool())
        .unwrap_or(true); // Enabled by default

    let half_life_days = args
        .get("halfLifeDays")
        .and_then(|v| v.as_f64())
        .unwrap_or(DEFAULT_HALF_LIFE_DAYS);

    debug!(max_results, min_score, use_recency, half_life_days, "Searching memory");

    // Build index and search
    let index = crate::memory::MemoryIndex::index_workspace(workspace_dir)?;
    
    let results = if use_recency {
        index.search_with_decay(query, max_results, half_life_days)
    } else {
        index.search(query, max_results)
    };

    if results.is_empty() {
        return Ok("No matching memories found.".to_string());
    }

    // Filter by minimum score and format results
    let mut output = String::new();
    output.push_str(&format!("Memory search results for: {}\n", query));
    if use_recency {
        output.push_str(&format!("(recency boost enabled, half-life: {} days)\n", half_life_days));
    }
    output.push('\n');

    let mut count = 0;
    for result in results {
        if result.score < min_score {
            continue;
        }
        count += 1;

        // Truncate snippet to ~700 chars
        let snippet = if result.chunk.text.len() > 700 {
            format!("{}...", &result.chunk.text[..700])
        } else {
            result.chunk.text.clone()
        };

        output.push_str(&format!(
            "{}. **{}** (lines {}-{}, score: {:.2})\n",
            count,
            result.chunk.path,
            result.chunk.start_line,
            result.chunk.end_line,
            result.score
        ));
        output.push_str(&format!("{}\n\n", snippet));
        output.push_str(&format!(
            "Source: {}#L{}-L{}\n\n",
            result.chunk.path, result.chunk.start_line, result.chunk.end_line
        ));
    }

    if count == 0 {
        debug!("No results above minimum score threshold");
        return Ok("No matching memories found above the minimum score threshold.".to_string());
    }

    debug!(result_count = count, "Memory search complete");
    Ok(output)
}

/// Read content from a memory file.
#[instrument(skip(args, workspace_dir))]
pub fn exec_memory_get(args: &Value, workspace_dir: &Path) -> Result<String, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: path".to_string())?;

    let from_line = args
        .get("from")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);

    let num_lines = args
        .get("lines")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);

    debug!(path, from_line, num_lines, "Reading memory file");

    crate::memory::read_memory_file(workspace_dir, path, from_line, num_lines)
}
