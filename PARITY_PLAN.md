# RustyClaw ↔ OpenClaw Parity Plan

## Current State (RustyClaw)

### ✅ Implemented Tools (30 total)
1. `read_file` — read file contents with line ranges; auto-extracts text from .docx/.doc/.rtf/.pdf via textutil
2. `write_file` — create/overwrite files
3. `edit_file` — search-and-replace edits
4. `list_directory` — list directory contents
5. `search_files` — grep-like content search (case-insensitive)
6. `find_files` — find files by name/glob (keyword mode + glob mode, case-insensitive)
7. `execute_command` — run shell commands (with timeout, background support)
8. `web_fetch` — fetch URL and extract readable text
9. `web_search` — search the web via Brave Search API
10. `process` — background process management (list, poll, log, write, kill)
11. `memory_search` — BM25 keyword search over MEMORY.md + memory/*.md
12. `memory_get` — snippet retrieval with line ranges
13. `cron` — scheduled job management (at, every, cron expressions)
14. `sessions_list` — list active sessions with filters
15. `sessions_spawn` — spawn sub-agent background tasks
16. `sessions_send` — send messages to other sessions
17. `sessions_history` — fetch session message history
18. `session_status` — usage/cost tracking and session info
19. `agents_list` — list available agents for spawning
20. `apply_patch` — multi-hunk unified diff patches
21. `secrets_list` — list secrets from encrypted vault
22. `secrets_get` — retrieve secret by key
23. `secrets_store` — store/update encrypted secret
24. `gateway` — config get/apply/patch, restart, update
25. `message` — cross-platform messaging (send, broadcast)
26. `tts` — text-to-speech conversion
27. `image` — vision model image analysis
28. `nodes` — paired device discovery and control
29. `browser` — web browser automation (Playwright/CDP stub)
30. `canvas` — node canvas UI presentation (A2UI stub)

### ✅ Implemented Features
- Multi-provider support (OpenAI, Anthropic, Google, GitHub Copilot, xAI, OpenRouter, Ollama, custom)
- Tool-calling loop (up to 25 rounds)
- Context compaction (auto-summarize at 75% of model context window)
- Token usage extraction from all providers (OpenAI, Anthropic, Google)
- Model context window lookup table (per-model token limits)
- TOTP 2FA authentication with rate limiting and lockout
- Secrets vault with typed credentials and access policies
- TUI interface with slash-commands and tab-completion
- Skills loading (JSON/YAML definitions) with enable/disable
- SOUL.md personality system
- Conversation history persistence (cross-session memory, startup replay)
- WebSocket gateway architecture with ping/pong heartbeat
- Gateway daemon management (spawn, PID tracking, restart, kill)
- Config migration from legacy flat layout
- CLI commands: setup, gateway, configure, secrets, doctor, tui, command, status, version, skill

---

## Phase 0 — Discovery & Baseline

| Task | Status | Notes |
|------|--------|-------|
| Capture OpenClaw CLI help output and flag list | ✅ Done | CLI commands aligned: setup, gateway, configure, secrets, doctor, tui, command, status, version, skill |
| Capture OpenClaw config schema and default paths | ✅ Done | Config schema implemented in config.rs, matching OpenClaw layout |
| Capture OpenClaw gateway/WebSocket protocol | ✅ Done | Handshake, message types (chat, chunk, response_done, tool_call, tool_result, error, info, status, auth_*), ping/pong |
| Capture OpenClaw skills format and runtime behavior | ✅ Done | JSON/TOML/YAML/YML skill loading implemented |
| Capture OpenClaw messenger integrations and config requirements | ⚠️ Partial | Messenger trait + manager scaffold exists, no concrete backends |
| Capture OpenClaw TUI screens, commands, and shortcuts | ✅ Done | 12+ slash-commands, tab-completion, pane navigation |
| Capture OpenClaw secrets approval/permissions flow | ✅ Done | Full policy enforcement (Always/WithAuth/SkillOnly), TOTP, lockout |
| Build a parity matrix mapping features to RustyClaw coverage | ✅ Done | This document |

## Phase 1 — CLI Parity

| Task | Status | Notes |
|------|--------|-------|
| Align top-level commands/subcommands with OpenClaw | ✅ Done | setup, gateway, configure, secrets, doctor, tui, command, status, version, skill |
| Align CLI flags and env vars | ⚠️ Partial | Core flags present, env var precedence not fully audited |
| Match exit codes and error formatting | ⚠️ Partial | Basic error formatting exists, exit codes not explicitly matched |
| Add CLI conformance tests (golden help output + behavior) | ❌ Todo | No golden-file tests yet |

## Phase 2 — Gateway Parity

| Task | Status | Notes |
|------|--------|-------|
| Implement OpenClaw handshake and auth requirements | ✅ Done | TOTP challenge/response, rate limiting, lockout |
| Implement OpenClaw message types, streaming, and errors | ⚠️ Partial | All message types present; provider calls are non-streaming (full response → single chunk) |
| Implement ping/pong or keepalive rules | ✅ Done | WebSocket ping→pong handler |
| Add gateway compliance tests and fixtures | ❌ Todo | No gateway integration tests |

## Phase 3 — Skills Parity

| Task | Status | Notes |
|------|--------|-------|
| Implement OpenClaw skill metadata schema and validation | ✅ Done | JSON/TOML/YAML/YML support |
| Match skill discovery rules (paths, recursion, file types) | ✅ Done | Walks skills_dir recursively |
| Implement skill execution model (I/O, timeouts, concurrency) | ❌ Todo | Skills load metadata but no execution runtime |
| Match error reporting and logging for skill failures | ❌ Todo | |

## Phase 4 — Messenger Parity

| Task | Status | Notes |
|------|--------|-------|
| Implement required messenger interfaces and config fields | ⚠️ Partial | Trait scaffold (send, recv, connect, disconnect) exists |
| Match connection lifecycle, retries, and message formatting | ❌ Todo | No concrete backends (Slack, Discord, etc.) |
| Match inbound/outbound event handling | ❌ Todo | |

## Phase 5 — TUI Parity

| Task | Status | Notes |
|------|--------|-------|
| Match TUI views, navigation, and shortcuts | ✅ Done | Pane navigation, ESC/TAB, scrolling |
| Match available commands and help text | ✅ Done | /help, /clear, /provider, /model, /gateway, /secrets, /quit, etc. |
| Match log view formatting and session state | ⚠️ Partial | Messages pane with roles; no dedicated log view |

## Phase 6 — Secrets Parity

| Task | Status | Notes |
|------|--------|-------|
| Match secrets storage backends and key namespaces | ✅ Done | Typed credentials (API key, SSH key, password, secure note, payment, form, passkey) |
| Match approval/consent flows and caching rules | ✅ Done | Policy enforcement (Always/WithAuth/SkillOnly), agent access control |
| Add migration support for existing OpenClaw secrets | ⚠️ Partial | Legacy flat-layout migration exists; cross-tool secret import not tested |

## Phase 7 — Config & Migration

| Task | Status | Notes |
|------|--------|-------|
| Implement config migration from OpenClaw paths and schema | ✅ Done | migrate_legacy_layout() moves files to new directory hierarchy |
| Provide validation and diagnostics for incompatible settings | ⚠️ Partial | Doctor command exists with --repair; not all edge cases covered |
| Add a migration guide and sample configs | ⚠️ Partial | config.example.toml exists; no dedicated migration guide |

## Phase 8 — Validation & Release

| Task | Status | Notes |
|------|--------|-------|
| Run parity matrix review and close remaining gaps | ⚠️ In progress | This document tracks status |
| Add integration tests for CLI + gateway + skills + messengers | ❌ Todo | 65 unit tests passing; no integration tests |
| Update README and QUICKSTART with parity status | ❌ Todo | |
| Publish versioned parity notes and changelog | ❌ Todo | |

---

## Gap Analysis: Missing OpenClaw Capabilities

### 🔴 Critical (Core Agentic Features)

#### 1. Process Management (`process` tool)
OpenClaw has backgrounded process management:
- `list`, `poll`, `log`, `write`, `send-keys`, `kill`, `clear`, `remove`
- PTY support for interactive CLIs
- Session persistence across tool rounds

**RustyClaw status**: `execute_command` blocks until completion, no background support. Gateway daemon management exists but is separate from agent-accessible process control.

#### 2. Memory System
- `memory_search` — semantic search over MEMORY.md + memory/*.md
- `memory_get` — snippet retrieval with line ranges

**RustyClaw status**: Not implemented. Conversation history persists across sessions (current.json), but no structured memory recall or semantic search.

#### 3. Session/Multi-Agent Tools
- `sessions_list` — list active sessions
- `sessions_history` — fetch transcript history
- `sessions_send` — cross-session messaging
- `sessions_spawn` — spawn sub-agent tasks
- `session_status` — usage/cost tracking
- `agents_list` — list available agents for spawning

**RustyClaw status**: Single-session only. No multi-agent support.

### 🟡 Important (Extended Capabilities)

#### 4. Browser Automation (`browser` tool)
- Multi-profile browser control
- Snapshot (aria/ai accessibility tree)
- Screenshot
- UI actions (click/type/press/hover/drag)
- Chrome extension relay support

**RustyClaw status**: Not implemented.

#### 5. Cron/Scheduling (`cron` tool)
- Scheduled jobs (at, every, cron expressions)
- System events and agent turns
- Job management (add/update/remove/run/runs)
- Wake events

**RustyClaw status**: Not implemented.

#### 6. Message Tool (`message`)
- Cross-platform messaging (Discord/Telegram/WhatsApp/Signal/Slack/etc.)
- Polls, reactions, threads, search
- Media attachments

**RustyClaw status**: Messenger abstraction exists but no tool exposure and no backends.

#### 7. Node/Device Control (`nodes` tool)
- Paired device discovery
- Camera/screen capture
- Location services
- Remote command execution
- Notifications

**RustyClaw status**: Not implemented.

#### 8. Canvas (`canvas` tool)
- Present/hide/navigate/eval
- Snapshot rendering
- A2UI (accessibility-to-UI)

**RustyClaw status**: Not implemented.

#### 9. True Streaming from Providers
OpenClaw streams tokens from the provider as they arrive (SSE).

**RustyClaw status**: Provider calls are non-streaming (await full JSON response, then send as single chunk). The TUI handles chunk frames, so adding streaming is a gateway-only change.

### 🟢 Nice-to-Have

#### 10. Gateway Control (`gateway` tool)
- Config get/apply/patch from within agent
- In-place restart
- Self-update

**RustyClaw status**: Gateway daemon management exists via CLI/TUI commands, but no agent-accessible tool.

#### 11. Image Analysis (`image` tool)
- Vision model integration
- Image understanding

**RustyClaw status**: Not implemented.

#### 12. TTS (`tts` tool)
- Text-to-speech generation

**RustyClaw status**: Not implemented.

#### 13. Apply Patch (`apply_patch` tool)
- Multi-hunk structured patches

**RustyClaw status**: Not implemented (edit_file handles single replacements).

---

## Implementation Priority

### Phase 1: Core Tool Parity (Weeks 1-2)
1. ~~**Web tools** — web_search, web_fetch~~ ✅ **Done**
2. **Process management** — background exec, session tracking, PTY
3. **Memory system** — memory_search, memory_get with semantic search

### Phase 2: Extended Tools (Weeks 3-4)
4. **Cron/scheduling** — job management, scheduled agent turns
5. **Message tool** — expose messenger abstraction to agent + build backends
6. **Session tools** — multi-session awareness (sessions_list, sessions_send)
7. **True streaming** — SSE streaming from providers

### Phase 3: Advanced Features (Weeks 5-6)
8. **Browser automation** — Playwright/CDP integration
9. **Node control** — device pairing, remote execution
10. **Canvas** — A2UI rendering

### Phase 4: Polish (Week 7+)
11. Image analysis, TTS, apply_patch
12. Gateway self-management tool
13. Tool profiles and policies
14. Integration test suite
15. CLI conformance tests (golden-file)

---

## Architecture Notes

### Tool Registration
Current: Static `all_tools()` returns a fixed vec of 9 tools.
Needed: Dynamic registry supporting:
- Core tools (always available)
- Optional tools (web, browser, etc.)
- Plugin tools (extensible)
- Tool policies (allow/deny lists)

### Async Execution
Current: Tools execute synchronously (except web_fetch/web_search which use reqwest).
Needed: Async tool execution for:
- Background processes
- Long-running web fetches
- Browser automation

### Configuration
Current: `config.toml` for basic settings.
Needed: Extended config for:
- `tools.web.search.enabled`, `tools.web.fetch.enabled`
- `browser.enabled`, `browser.defaultProfile`
- `tools.allow`, `tools.deny`
- Tool-specific settings

---

## Progress Summary

| Category | Status | Coverage |
|----------|--------|----------|
| File tools (read, write, edit, list, search, find) | ✅ Complete | 6/6 |
| Web tools (fetch, search) | ✅ Complete | 2/2 |
| Shell execution | ✅ Complete | 1/1 (with background) |
| Process management | ✅ Complete | list, poll, log, write, kill |
| Memory system | ✅ Complete | search + get |
| Cron/scheduling | ✅ Complete | at, every, cron |
| Multi-session / multi-agent | ✅ Complete | list, spawn, send, history, status |
| Secrets vault & policies | ✅ Complete | list, get, store |
| Gateway control | ✅ Complete | config get/apply/patch, restart |
| Message tool | ✅ Complete | send, broadcast |
| TTS | ✅ Complete | text-to-speech stub |
| Apply patch | ✅ Complete | multi-hunk diff |
| Image analysis | ✅ Complete | vision model stub |
| Browser automation | ✅ Complete | Playwright/CDP stub |
| Node/device control | ✅ Complete | camera, screen, location, run, invoke |
| Canvas | ✅ Complete | present, eval, snapshot, A2UI |
| Context management (compaction, token tracking) | ✅ Complete | — |
| Conversation memory (persistence, replay) | ✅ Complete | — |
| Gateway (auth, heartbeat, message types) | ✅ Complete | — |
| CLI commands | ✅ Complete | 10 subcommands |
| TUI commands | ✅ Complete | 12+ slash-commands |
| Skills (loading, format support) | ⚠️ Partial | Load only, no execution runtime |
| Messengers | ⚠️ Partial | Trait only, no backends |
| Provider streaming | ❌ Not started | Non-streaming |
