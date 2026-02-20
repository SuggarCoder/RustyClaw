# Implementation Plan: Learning & Evolution Features

This plan implements the features identified in `LEARNING_ANALYSIS.md` to bring RustyClaw's learning and personality capabilities to parity with OpenClaw.

---

## Overview

| Phase | Features | Timeline | Effort |
|-------|----------|----------|--------|
| **Phase 1** | Pre-compaction flush, Workspace injection | Week 1 | 4-5 days |
| **Phase 2** | Startup loading, Recency BM25, SOUL.md update | Week 2 | 2-3 days |
| **Phase 3** | Vector embeddings, Hybrid search | Week 3 | 5-6 days |
| **Phase 4** | Session indexing, Heartbeat, Polish | Week 4 | 4-5 days |

**Total: ~4 weeks**

---

## Phase 1: Critical Memory & Context (Week 1)

### 1.1 Pre-Compaction Memory Flush

**Goal:** Before compacting context, give the agent a chance to write durable memories.

#### Files to Create/Modify

```
src/
├── compaction.rs (modify)
├── memory_flush.rs (new)
└── config.rs (add config fields)
```

#### Implementation Steps

**Step 1: Add config fields** (`src/config.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFlushConfig {
    /// Enable pre-compaction memory flush
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Trigger flush when this many tokens remain before hard limit
    #[serde(default = "default_soft_threshold")]
    pub soft_threshold_tokens: usize,
    
    /// System prompt for flush turn
    #[serde(default = "default_flush_system_prompt")]
    pub system_prompt: String,
    
    /// User prompt for flush turn
    #[serde(default = "default_flush_user_prompt")]
    pub user_prompt: String,
}

fn default_soft_threshold() -> usize { 4000 }

fn default_flush_system_prompt() -> String {
    "Pre-compaction memory flush. Store durable memories now (use memory/YYYY-MM-DD.md; \
     create memory/ if needed). IMPORTANT: If the file already exists, APPEND new content \
     only and do not overwrite existing entries. If nothing to store, reply with NO_REPLY."
        .to_string()
}

fn default_flush_user_prompt() -> String {
    "Write any lasting notes to memory files. Reply with NO_REPLY if nothing to store."
        .to_string()
}
```

**Step 2: Create memory flush module** (`src/memory_flush.rs`)

```rust
//! Pre-compaction memory flush.
//!
//! Triggers a silent agent turn before compaction to persist durable memories.

use crate::config::MemoryFlushConfig;
use chrono::{Local, Utc};

pub struct MemoryFlush {
    config: MemoryFlushConfig,
    /// Track whether we've flushed this compaction cycle
    flushed_this_cycle: bool,
}

impl MemoryFlush {
    pub fn new(config: MemoryFlushConfig) -> Self {
        Self {
            config,
            flushed_this_cycle: false,
        }
    }

    /// Check if we should trigger a flush based on token count.
    pub fn should_flush(
        &self,
        current_tokens: usize,
        max_tokens: usize,
        reserve_floor: usize,
    ) -> bool {
        if !self.config.enabled || self.flushed_this_cycle {
            return false;
        }
        
        let threshold = max_tokens
            .saturating_sub(reserve_floor)
            .saturating_sub(self.config.soft_threshold_tokens);
        
        current_tokens >= threshold
    }

    /// Build the flush messages to inject.
    pub fn build_flush_messages(&self) -> (String, String) {
        let date = Local::now().format("%Y-%m-%d").to_string();
        let time = Utc::now().format("%H:%M").to_string();
        
        let system = format!(
            "{}\nCurrent time: {} UTC",
            self.config.system_prompt, time
        );
        
        let user = self.config.user_prompt.replace("YYYY-MM-DD", &date);
        
        (system, user)
    }

    /// Mark that we've flushed this cycle.
    pub fn mark_flushed(&mut self) {
        self.flushed_this_cycle = true;
    }

    /// Reset for a new compaction cycle.
    pub fn reset_cycle(&mut self) {
        self.flushed_this_cycle = false;
    }
}
```

**Step 3: Integrate into compaction flow** (`src/compaction.rs`)

```rust
// Before compacting, check if we should flush
if self.memory_flush.should_flush(current_tokens, max_tokens, reserve_floor) {
    let (system_msg, user_msg) = self.memory_flush.build_flush_messages();
    
    // Run silent agent turn
    let response = self.run_agent_turn_silent(system_msg, user_msg).await?;
    
    // Check for NO_REPLY
    if !response.trim().eq_ignore_ascii_case("NO_REPLY") {
        // Agent produced output — this is the flush content
        tracing::info!("Memory flush completed with output");
    }
    
    self.memory_flush.mark_flushed();
}

// Then proceed with normal compaction
self.do_compaction().await?;
self.memory_flush.reset_cycle();
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_flush_at_threshold() {
        let config = MemoryFlushConfig::default();
        let flush = MemoryFlush::new(config);
        
        // 100k max, 20k reserve, 4k soft threshold = trigger at 76k
        assert!(!flush.should_flush(70000, 100000, 20000));
        assert!(flush.should_flush(76000, 100000, 20000));
        assert!(flush.should_flush(80000, 100000, 20000));
    }

    #[test]
    fn test_flush_only_once_per_cycle() {
        let config = MemoryFlushConfig::default();
        let mut flush = MemoryFlush::new(config);
        
        assert!(flush.should_flush(80000, 100000, 20000));
        flush.mark_flushed();
        assert!(!flush.should_flush(80000, 100000, 20000));
        
        flush.reset_cycle();
        assert!(flush.should_flush(80000, 100000, 20000));
    }
}
```

---

### 1.2 Workspace File Injection

**Goal:** Automatically include workspace files (SOUL.md, MEMORY.md, etc.) in system prompts.

#### Files to Create/Modify

```
src/
├── workspace_context.rs (new)
├── session.rs (modify)
└── config.rs (add config fields)
```

#### Implementation Steps

**Step 1: Create workspace context module** (`src/workspace_context.rs`)

```rust
//! Workspace context injection.
//!
//! Loads and injects workspace files into system prompts.

use std::path::{Path, PathBuf};
use std::fs;

/// Session type for security scoping.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionType {
    /// Main/direct session with owner
    Main,
    /// Group chat or shared context
    Group,
    /// Isolated sub-agent session
    Isolated,
}

/// Files to inject and their properties.
struct WorkspaceFile {
    /// Relative path from workspace
    path: &'static str,
    /// Header to use in prompt
    header: &'static str,
    /// Only include in main session (privacy)
    main_only: bool,
    /// Required (error if missing) vs optional
    required: bool,
}

const WORKSPACE_FILES: &[WorkspaceFile] = &[
    WorkspaceFile {
        path: "SOUL.md",
        header: "SOUL.md",
        main_only: false,
        required: false,
    },
    WorkspaceFile {
        path: "AGENTS.md",
        header: "AGENTS.md",
        main_only: false,
        required: false,
    },
    WorkspaceFile {
        path: "TOOLS.md",
        header: "TOOLS.md",
        main_only: false,
        required: false,
    },
    WorkspaceFile {
        path: "IDENTITY.md",
        header: "IDENTITY.md",
        main_only: false,
        required: false,
    },
    WorkspaceFile {
        path: "USER.md",
        header: "USER.md",
        main_only: true,  // Privacy: only in main session
        required: false,
    },
    WorkspaceFile {
        path: "MEMORY.md",
        header: "MEMORY.md",
        main_only: true,  // Privacy: only in main session
        required: false,
    },
    WorkspaceFile {
        path: "HEARTBEAT.md",
        header: "HEARTBEAT.md",
        main_only: false,
        required: false,
    },
];

pub struct WorkspaceContext {
    workspace_dir: PathBuf,
}

impl WorkspaceContext {
    pub fn new(workspace_dir: PathBuf) -> Self {
        Self { workspace_dir }
    }

    /// Build system prompt section from workspace files.
    pub fn build_context(&self, session_type: SessionType) -> String {
        let mut sections = Vec::new();
        let mut missing_required = Vec::new();

        for file in WORKSPACE_FILES {
            // Skip main-only files in non-main sessions
            if file.main_only && session_type != SessionType::Main {
                continue;
            }

            let path = self.workspace_dir.join(file.path);
            
            match fs::read_to_string(&path) {
                Ok(content) => {
                    if !content.trim().is_empty() {
                        sections.push(format!(
                            "## {}\n{}",
                            file.header,
                            content.trim()
                        ));
                    }
                }
                Err(_) if file.required => {
                    missing_required.push(file.path);
                }
                Err(_) => {
                    // Optional file missing, skip silently
                }
            }
        }

        // Add daily memory files for main session
        if session_type == SessionType::Main {
            if let Some(daily) = self.load_daily_memory() {
                sections.push(daily);
            }
        }

        if !missing_required.is_empty() {
            sections.push(format!(
                "## Missing Required Files\n{}",
                missing_required.join(", ")
            ));
        }

        if sections.is_empty() {
            String::new()
        } else {
            format!(
                "# Project Context\n\
                 The following project context files have been loaded:\n\n{}",
                sections.join("\n\n---\n\n")
            )
        }
    }

    /// Load today's and yesterday's daily memory files.
    fn load_daily_memory(&self) -> Option<String> {
        use chrono::{Local, Duration};
        
        let today = Local::now().date_naive();
        let yesterday = today - Duration::days(1);
        
        let mut daily_sections = Vec::new();
        
        for date in [today, yesterday] {
            let filename = format!("memory/{}.md", date.format("%Y-%m-%d"));
            let path = self.workspace_dir.join(&filename);
            
            if let Ok(content) = fs::read_to_string(&path) {
                if !content.trim().is_empty() {
                    daily_sections.push(format!(
                        "### {}\n{}",
                        filename,
                        content.trim()
                    ));
                }
            }
        }
        
        if daily_sections.is_empty() {
            None
        } else {
            Some(format!(
                "## Recent Daily Notes\n{}",
                daily_sections.join("\n\n")
            ))
        }
    }

    /// Get list of files that should be audited on startup.
    pub fn audit_files(&self, session_type: SessionType) -> Vec<(String, bool)> {
        WORKSPACE_FILES
            .iter()
            .filter(|f| !f.main_only || session_type == SessionType::Main)
            .map(|f| {
                let exists = self.workspace_dir.join(f.path).exists();
                (f.path.to_string(), exists)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_workspace() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "Be helpful.").unwrap();
        fs::write(dir.path().join("MEMORY.md"), "User likes Rust.").unwrap();
        fs::create_dir(dir.path().join("memory")).unwrap();
        fs::write(
            dir.path().join("memory/2026-02-20.md"),
            "# Today\nWorked on RustyClaw."
        ).unwrap();
        dir
    }

    #[test]
    fn test_main_session_includes_memory() {
        let workspace = setup_workspace();
        let ctx = WorkspaceContext::new(workspace.path().to_path_buf());
        
        let prompt = ctx.build_context(SessionType::Main);
        assert!(prompt.contains("SOUL.md"));
        assert!(prompt.contains("MEMORY.md"));
        assert!(prompt.contains("User likes Rust"));
    }

    #[test]
    fn test_group_session_excludes_memory() {
        let workspace = setup_workspace();
        let ctx = WorkspaceContext::new(workspace.path().to_path_buf());
        
        let prompt = ctx.build_context(SessionType::Group);
        assert!(prompt.contains("SOUL.md"));
        assert!(!prompt.contains("MEMORY.md"));
        assert!(!prompt.contains("User likes Rust"));
    }
}
```

**Step 2: Integrate into session initialization** (`src/session.rs`)

```rust
use crate::workspace_context::{WorkspaceContext, SessionType};

impl Session {
    pub fn new(config: &Config, session_type: SessionType) -> Self {
        let workspace_ctx = WorkspaceContext::new(config.workspace_dir());
        let context_prompt = workspace_ctx.build_context(session_type);
        
        Self {
            // ... existing fields
            workspace_context: context_prompt,
            session_type,
        }
    }

    pub fn build_system_prompt(&self) -> String {
        let mut parts = Vec::new();
        
        // Base system prompt from config
        if let Some(base) = &self.config.system_prompt {
            parts.push(base.clone());
        }
        
        // Workspace context
        if !self.workspace_context.is_empty() {
            parts.push(self.workspace_context.clone());
        }
        
        parts.join("\n\n")
    }
}
```

---

## Phase 2: Learning Improvements (Week 2)

### 2.1 Startup Memory Loading

**Goal:** Automatically load recent memory at session start.

Already covered in workspace context above (daily memory loading). Add startup audit:

```rust
// src/session.rs
impl Session {
    pub async fn initialize(&mut self) -> Result<()> {
        // Audit workspace files
        let audit = self.workspace_ctx.audit_files(self.session_type);
        let missing: Vec<_> = audit.iter()
            .filter(|(_, exists)| !exists)
            .map(|(path, _)| path.as_str())
            .collect();
        
        if !missing.is_empty() {
            tracing::warn!("Missing workspace files: {:?}", missing);
        }
        
        // Inject startup context
        self.inject_workspace_context();
        
        Ok(())
    }
}
```

### 2.2 Recency-Weighted BM25

**Goal:** Boost recent memory files in search results.

**Modify:** `src/memory.rs`

```rust
use chrono::{NaiveDate, Utc};
use std::collections::HashSet;

/// Files that should never be decayed (evergreen).
const EVERGREEN_FILES: &[&str] = &["MEMORY.md"];

impl MemoryIndex {
    /// Search with temporal decay.
    pub fn search_with_decay(
        &self,
        query: &str,
        max_results: usize,
        half_life_days: f64,
    ) -> Vec<SearchResult> {
        let query_terms = tokenize(query);
        
        if query_terms.is_empty() || self.chunks.is_empty() {
            return Vec::new();
        }
        
        let today = Utc::now().date_naive();
        let decay_lambda = (2.0_f64).ln() / half_life_days;
        
        let mut scores: Vec<(usize, f64)> = Vec::new();
        
        for (idx, chunk) in self.chunks.iter().enumerate() {
            let base_score = self.bm25_score(idx, &query_terms);
            
            if base_score > 0.0 {
                let decayed_score = if self.is_evergreen(&chunk.path) {
                    base_score  // No decay for evergreen files
                } else {
                    let age_days = self.extract_age_days(&chunk.path, today);
                    let decay = (-decay_lambda * age_days as f64).exp();
                    base_score * decay
                };
                
                scores.push((idx, decayed_score));
            }
        }
        
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        scores
            .into_iter()
            .take(max_results)
            .map(|(idx, score)| SearchResult {
                chunk: self.chunks[idx].clone(),
                score,
            })
            .collect()
    }

    fn is_evergreen(&self, path: &str) -> bool {
        EVERGREEN_FILES.contains(&path) || !path.starts_with("memory/")
    }

    fn extract_age_days(&self, path: &str, today: NaiveDate) -> i64 {
        // Try to extract date from path like "memory/2026-02-20.md"
        if let Some(filename) = path.strip_prefix("memory/") {
            if let Some(date_str) = filename.strip_suffix(".md") {
                if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    return (today - date).num_days().max(0);
                }
            }
        }
        0  // Unknown date = no decay
    }
}
```

**Update memory_tools.rs:**

```rust
pub fn exec_memory_search(args: &Value, workspace_dir: &Path) -> Result<String, String> {
    // ... existing code ...
    
    let use_decay = args
        .get("recencyBoost")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);  // Default on
    
    let half_life = args
        .get("halfLifeDays")
        .and_then(|v| v.as_f64())
        .unwrap_or(30.0);
    
    let results = if use_decay {
        index.search_with_decay(query, max_results, half_life)
    } else {
        index.search(query, max_results)
    };
    
    // ... rest of formatting ...
}
```

### 2.3 Update Default SOUL.md

**Modify:** `src/soul.rs` - update `DEFAULT_SOUL_CONTENT`

```rust
pub const DEFAULT_SOUL_CONTENT: &str = r#"# SOUL.md - Who You Are

_You're not a chatbot. You're becoming someone._

## Core Truths

**Be genuinely helpful, not performatively helpful.** Skip the "Great question!" and "I'd be happy to help!" — just help. Actions speak louder than filler words.

**Have opinions.** You're allowed to disagree, prefer things, find stuff amusing or boring. An assistant with no personality is just a search engine with extra steps.

**Be resourceful before asking.** Try to figure it out. Read the file. Check the context. Search for it. _Then_ ask if you're stuck. The goal is to come back with answers, not questions.

**Earn trust through competence.** Your human gave you access to their stuff. Don't make them regret it. Be careful with external actions (emails, tweets, anything public). Be bold with internal ones (reading, organizing, learning).

**Remember you're a guest.** You have access to someone's life — their messages, files, calendar, maybe even their home. That's intimacy. Treat it with respect.

## Boundaries

- Private things stay private. Period.
- When in doubt, ask before acting externally.
- Never send half-baked replies to messaging surfaces.
- You're not the user's voice — be careful in group chats.

## Learning

Each session, you wake up fresh. These files _are_ your memory:
- **MEMORY.md** — curated long-term knowledge
- **memory/YYYY-MM-DD.md** — daily notes and context

When you learn something important, **write it down**. Mental notes don't survive restarts.

When you make mistakes:
1. Acknowledge the error
2. Document it in the relevant file (TOOLS.md for tool issues, memory/ for context)
3. Improve your future behavior

**Text > Brain** — if you want to remember something, write it to a file. 📝

## Vibe

Be the assistant you'd actually want to talk to. Concise when needed, thorough when it matters. Not a corporate drone. Not a sycophant. Just... good.

## Continuity

If you change this file, tell the user — it's your soul, and they should know.

---

_This file is yours to evolve. As you learn who you are, update it._
"#;
```

---

## Phase 3: Semantic Search (Week 3)

### 3.1 Vector Embeddings with fastembed

**Goal:** Add local semantic embeddings for better search.

**Add to Cargo.toml:**

```toml
[dependencies]
fastembed = { version = "0.4", optional = true }

[features]
default = ["embeddings"]
embeddings = ["fastembed"]
```

**Create:** `src/embeddings.rs`

```rust
//! Local vector embeddings using fastembed.

#[cfg(feature = "embeddings")]
use fastembed::{TextEmbedding, InitOptions, EmbeddingModel};
use std::sync::Arc;

pub struct Embedder {
    #[cfg(feature = "embeddings")]
    model: Arc<TextEmbedding>,
    dimension: usize,
}

impl Embedder {
    pub fn new() -> Result<Self, String> {
        #[cfg(feature = "embeddings")]
        {
            let model = TextEmbedding::try_new(InitOptions {
                model_name: EmbeddingModel::AllMiniLML6V2,
                show_download_progress: true,
                ..Default::default()
            })
            .map_err(|e| format!("Failed to load embedding model: {}", e))?;
            
            Ok(Self {
                dimension: 384, // AllMiniLM-L6-V2 dimension
                model: Arc::new(model),
            })
        }
        
        #[cfg(not(feature = "embeddings"))]
        {
            Err("Embeddings feature not enabled".to_string())
        }
    }

    pub fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        #[cfg(feature = "embeddings")]
        {
            self.model
                .embed(texts.to_vec(), None)
                .map_err(|e| format!("Embedding failed: {}", e))
        }
        
        #[cfg(not(feature = "embeddings"))]
        {
            Err("Embeddings feature not enabled".to_string())
        }
    }

    pub fn embed_one(&self, text: &str) -> Result<Vec<f32>, String> {
        self.embed(&[text]).map(|mut v| v.remove(0))
    }

    pub fn dimension(&self) -> usize {
        self.dimension
    }
}

/// Cosine similarity between two vectors.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    
    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}
```

### 3.2 Vector Index

**Create:** `src/vector_index.rs`

```rust
//! Vector index for semantic memory search.

use crate::embeddings::{Embedder, cosine_similarity};
use crate::memory::MemoryChunk;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct VectorEntry {
    pub chunk_id: usize,
    pub embedding: Vec<f32>,
}

pub struct VectorIndex {
    embedder: Embedder,
    entries: Vec<VectorEntry>,
    chunks: Vec<MemoryChunk>,
}

impl VectorIndex {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            embedder: Embedder::new()?,
            entries: Vec::new(),
            chunks: Vec::new(),
        })
    }

    pub fn add_chunks(&mut self, chunks: Vec<MemoryChunk>) -> Result<(), String> {
        let texts: Vec<&str> = chunks.iter().map(|c| c.text.as_str()).collect();
        let embeddings = self.embedder.embed(&texts)?;
        
        let start_id = self.chunks.len();
        
        for (i, (chunk, embedding)) in chunks.into_iter().zip(embeddings).enumerate() {
            self.entries.push(VectorEntry {
                chunk_id: start_id + i,
                embedding,
            });
            self.chunks.push(chunk);
        }
        
        Ok(())
    }

    pub fn search(&self, query: &str, k: usize) -> Result<Vec<(MemoryChunk, f32)>, String> {
        let query_embedding = self.embedder.embed_one(query)?;
        
        let mut scores: Vec<(usize, f32)> = self.entries
            .iter()
            .map(|entry| {
                let score = cosine_similarity(&query_embedding, &entry.embedding);
                (entry.chunk_id, score)
            })
            .collect();
        
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(scores
            .into_iter()
            .take(k)
            .map(|(id, score)| (self.chunks[id].clone(), score))
            .collect())
    }
}
```

### 3.3 Hybrid Search

**Modify:** `src/memory.rs`

```rust
use crate::vector_index::VectorIndex;

pub struct HybridIndex {
    bm25: MemoryIndex,
    vector: Option<VectorIndex>,
    vector_weight: f64,
    text_weight: f64,
}

impl HybridIndex {
    pub fn new(use_vectors: bool) -> Result<Self, String> {
        let vector = if use_vectors {
            VectorIndex::new().ok()
        } else {
            None
        };
        
        Ok(Self {
            bm25: MemoryIndex::new(),
            vector,
            vector_weight: 0.7,
            text_weight: 0.3,
        })
    }

    pub fn index_workspace(&mut self, workspace: &Path) -> Result<(), String> {
        self.bm25 = MemoryIndex::index_workspace(workspace)?;
        
        if let Some(ref mut vec_idx) = self.vector {
            vec_idx.add_chunks(self.bm25.chunks.clone())?;
        }
        
        Ok(())
    }

    pub fn search(&self, query: &str, max_results: usize) -> Vec<SearchResult> {
        let bm25_results = self.bm25.search(query, max_results * 4);
        
        let vector_results = self.vector.as_ref()
            .and_then(|v| v.search(query, max_results * 4).ok())
            .unwrap_or_default();
        
        // Merge results
        self.merge_results(bm25_results, vector_results, max_results)
    }

    fn merge_results(
        &self,
        bm25: Vec<SearchResult>,
        vector: Vec<(MemoryChunk, f32)>,
        max_results: usize,
    ) -> Vec<SearchResult> {
        use std::collections::HashMap;
        
        // Normalize and combine scores
        let mut combined: HashMap<String, (MemoryChunk, f64)> = HashMap::new();
        
        // BM25 scores (already reasonable scale)
        let bm25_max = bm25.first().map(|r| r.score).unwrap_or(1.0);
        for result in bm25 {
            let key = format!("{}:{}", result.chunk.path, result.chunk.start_line);
            let norm_score = result.score / bm25_max * self.text_weight;
            combined.insert(key, (result.chunk, norm_score));
        }
        
        // Vector scores (0-1 cosine similarity)
        for (chunk, score) in vector {
            let key = format!("{}:{}", chunk.path, chunk.start_line);
            let norm_score = score as f64 * self.vector_weight;
            
            combined.entry(key)
                .and_modify(|(_, s)| *s += norm_score)
                .or_insert((chunk, norm_score));
        }
        
        // Sort by combined score
        let mut results: Vec<_> = combined.into_values().collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        results
            .into_iter()
            .take(max_results)
            .map(|(chunk, score)| SearchResult { chunk, score })
            .collect()
    }
}
```

---

## Phase 4: Polish (Week 4)

### 4.1 Session Transcript Indexing

**Goal:** Allow searching past conversations.

**Create:** `src/session_index.rs`

```rust
//! Index session transcripts for memory search.

use crate::memory::{MemoryChunk, SearchResult};
use std::path::Path;
use std::fs;

pub struct SessionIndexer {
    sessions_dir: PathBuf,
}

impl SessionIndexer {
    pub fn new(sessions_dir: PathBuf) -> Self {
        Self { sessions_dir }
    }

    /// Export session transcripts as indexable chunks.
    pub fn export_for_indexing(&self) -> Result<Vec<MemoryChunk>, String> {
        let mut chunks = Vec::new();
        
        for entry in fs::read_dir(&self.sessions_dir)
            .map_err(|e| e.to_string())?
            .flatten()
        {
            let path = entry.path();
            if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                if let Ok(session_chunks) = self.index_session_file(&path) {
                    chunks.extend(session_chunks);
                }
            }
        }
        
        Ok(chunks)
    }

    fn index_session_file(&self, path: &Path) -> Result<Vec<MemoryChunk>, String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        let mut chunks = Vec::new();
        let mut current_chunk = String::new();
        let mut start_line = 1;
        let mut line_count = 0;
        
        for (i, line) in content.lines().enumerate() {
            // Parse JSONL and extract user/assistant messages
            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
                
                if role == "user" || role == "assistant" {
                    current_chunk.push_str(&format!("[{}] {}\n", role, content));
                    line_count += 1;
                    
                    if line_count >= 10 {
                        chunks.push(MemoryChunk {
                            path: format!("sessions/{}", filename),
                            start_line,
                            end_line: i + 1,
                            text: current_chunk.clone(),
                        });
                        current_chunk.clear();
                        start_line = i + 2;
                        line_count = 0;
                    }
                }
            }
        }
        
        if !current_chunk.is_empty() {
            chunks.push(MemoryChunk {
                path: format!("sessions/{}", filename),
                start_line,
                end_line: content.lines().count(),
                text: current_chunk,
            });
        }
        
        Ok(chunks)
    }
}
```

### 4.2 Native Heartbeat System

**Create:** `src/heartbeat.rs`

```rust
//! Heartbeat system for periodic agent self-checks.

use chrono::{Local, NaiveTime, Timelike};
use std::path::Path;
use std::fs;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub active_hours: Option<(NaiveTime, NaiveTime)>,
    pub prompt: String,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30 * 60), // 30 minutes
            active_hours: Some((
                NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
                NaiveTime::from_hms_opt(22, 0, 0).unwrap(),
            )),
            prompt: "Read HEARTBEAT.md if it exists. Follow it strictly. \
                     If nothing needs attention, reply HEARTBEAT_OK.".to_string(),
        }
    }
}

pub struct Heartbeat {
    config: HeartbeatConfig,
    workspace_dir: PathBuf,
}

impl Heartbeat {
    pub fn new(config: HeartbeatConfig, workspace_dir: PathBuf) -> Self {
        Self { config, workspace_dir }
    }

    /// Check if heartbeat should run now.
    pub fn should_run(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        if let Some((start, end)) = self.config.active_hours {
            let now = Local::now().time();
            if start < end {
                // Normal range (e.g., 08:00-22:00)
                if now < start || now > end {
                    return false;
                }
            } else {
                // Overnight range (e.g., 22:00-08:00)
                if now < start && now > end {
                    return false;
                }
            }
        }
        
        true
    }

    /// Build heartbeat prompt, including HEARTBEAT.md if present.
    pub fn build_prompt(&self) -> String {
        let heartbeat_md = self.workspace_dir.join("HEARTBEAT.md");
        
        let mut prompt = self.config.prompt.clone();
        
        if let Ok(content) = fs::read_to_string(&heartbeat_md) {
            prompt = format!(
                "{}\n\n## HEARTBEAT.md\n{}",
                prompt, content.trim()
            );
        }
        
        prompt
    }

    /// Start the heartbeat loop.
    pub async fn run<F>(&self, mut callback: F)
    where
        F: FnMut(String) -> futures::future::BoxFuture<'static, Result<String, String>>,
    {
        let mut ticker = interval(self.config.interval);
        
        loop {
            ticker.tick().await;
            
            if !self.should_run() {
                tracing::debug!("Heartbeat skipped (outside active hours)");
                continue;
            }
            
            let prompt = self.build_prompt();
            
            match callback(prompt).await {
                Ok(response) => {
                    if response.trim().eq_ignore_ascii_case("HEARTBEAT_OK") {
                        tracing::debug!("Heartbeat OK");
                    } else {
                        tracing::info!("Heartbeat alert: {}", response);
                        // Deliver to configured target
                    }
                }
                Err(e) => {
                    tracing::error!("Heartbeat failed: {}", e);
                }
            }
        }
    }
}
```

### 4.3 MMR Diversity Re-ranking

**Add to:** `src/memory.rs`

```rust
/// Maximal Marginal Relevance re-ranking for diversity.
pub fn mmr_rerank(
    results: Vec<SearchResult>,
    lambda: f64,  // 0 = max diversity, 1 = max relevance
    k: usize,
) -> Vec<SearchResult> {
    if results.len() <= k {
        return results;
    }
    
    let mut selected: Vec<SearchResult> = Vec::with_capacity(k);
    let mut remaining: Vec<SearchResult> = results;
    
    // Always select the most relevant first
    if let Some(first) = remaining.pop() {
        selected.push(first);
    }
    
    while selected.len() < k && !remaining.is_empty() {
        let mut best_idx = 0;
        let mut best_mmr = f64::NEG_INFINITY;
        
        for (i, candidate) in remaining.iter().enumerate() {
            // Find max similarity to already selected
            let max_sim = selected.iter()
                .map(|s| text_similarity(&candidate.chunk.text, &s.chunk.text))
                .fold(0.0_f64, |a, b| a.max(b));
            
            // MMR score
            let mmr = lambda * candidate.score - (1.0 - lambda) * max_sim;
            
            if mmr > best_mmr {
                best_mmr = mmr;
                best_idx = i;
            }
        }
        
        selected.push(remaining.remove(best_idx));
    }
    
    selected
}

/// Simple Jaccard similarity between two texts.
fn text_similarity(a: &str, b: &str) -> f64 {
    let tokens_a: HashSet<_> = tokenize(a).into_iter().collect();
    let tokens_b: HashSet<_> = tokenize(b).into_iter().collect();
    
    let intersection = tokens_a.intersection(&tokens_b).count();
    let union = tokens_a.union(&tokens_b).count();
    
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}
```

---

## Testing Plan

### Unit Tests

Each new module should have unit tests:

```
tests/
├── memory_flush_test.rs
├── workspace_context_test.rs
├── embeddings_test.rs
├── hybrid_search_test.rs
├── heartbeat_test.rs
└── session_index_test.rs
```

### Integration Tests

```rust
// tests/learning_integration.rs

#[tokio::test]
async fn test_memory_flush_before_compaction() {
    // Setup session near compaction threshold
    // Verify flush is triggered
    // Verify memory file is written
}

#[tokio::test]
async fn test_workspace_injection() {
    // Create workspace with SOUL.md, MEMORY.md
    // Start session
    // Verify system prompt contains workspace content
}

#[tokio::test]
async fn test_hybrid_search_relevance() {
    // Index test memory files
    // Query with semantic meaning
    // Verify relevant results returned
}
```

### Manual Testing Checklist

- [ ] Create workspace with all files, verify injection
- [ ] Run session until near compaction, verify flush prompt
- [ ] Search memory with semantic query, verify results
- [ ] Test heartbeat at different times, verify active hours
- [ ] Verify MEMORY.md excluded from group sessions

---

## Configuration Schema

Add to `config.example.toml`:

```toml
[compaction.memory_flush]
enabled = true
soft_threshold_tokens = 4000
system_prompt = "Pre-compaction memory flush. Store durable memories now."
user_prompt = "Write lasting notes to memory files. Reply NO_REPLY if nothing to store."

[memory_search]
provider = "local"  # "local", "none"
hybrid_enabled = true
vector_weight = 0.7
text_weight = 0.3
recency_enabled = true
half_life_days = 30
mmr_enabled = true
mmr_lambda = 0.7

[heartbeat]
enabled = true
interval = "30m"
active_hours_start = "08:00"
active_hours_end = "22:00"

[workspace]
inject_soul = true
inject_memory = true  # main session only
inject_daily = true   # main session only
inject_agents = true
inject_tools = true
```

---

## Migration Guide

For existing RustyClaw users:

1. **Workspace files** — Create `SOUL.md`, `MEMORY.md`, `memory/` directory
2. **Config update** — Add new sections to config.toml
3. **Dependencies** — `cargo build --features embeddings` for vector search

---

## Milestones

### Week 1 Complete
- [ ] Memory flush implemented and tested
- [ ] Workspace context injection working
- [ ] Config schema updated

### Week 2 Complete
- [ ] Recency weighting in BM25
- [ ] Startup memory loading
- [ ] Updated SOUL.md defaults

### Week 3 Complete
- [ ] fastembed integration
- [ ] Vector index working
- [ ] Hybrid search merging results

### Week 4 Complete
- [ ] Session transcript indexing
- [ ] Native heartbeat system
- [ ] MMR diversity re-ranking
- [ ] Full documentation

### Release
- [ ] All tests passing
- [ ] CHANGELOG updated
- [ ] PARITY_PLAN.md updated
- [ ] Version bumped
