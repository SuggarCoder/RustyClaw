# RustyClaw Background Tasks — Design Plan

## Overview

Background tasks allow the main agent to spawn isolated work that runs without blocking the primary chat flow. Tasks can receive context, perform work, and return results.

## Core Concepts

### Task Lifecycle
```
SPAWNED → RUNNING → COMPLETED | FAILED | KILLED
                  ↘ TIMEOUT
```

### Task Identity
- **task_id**: UUID, auto-generated on spawn
- **label**: Optional human-friendly name (e.g., "epstein-research", "code-review-pr-42")
- Tasks are scoped to a session — each requester session has its own task namespace

## Tools

### 1. `task_spawn`
Spawn a new background task.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task` | string | ✓ | The instruction/prompt for the background task |
| `label` | string | | Human-friendly identifier |
| `context` | string | | Additional context to pass (file contents, data, etc.) |
| `model` | string | | Override model for this task |
| `timeout_secs` | u64 | | Task timeout (default: 3600 = 1 hour) |
| `notify` | bool | | Push notification on completion (default: true) |
| `thinking` | string | | Thinking level: "off", "low", "medium", "high" |

**Returns:**
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "label": "epstein-research",
  "status": "spawned"
}
```

**Example:**
```
task_spawn(
  task: "Research all mentions of 'Drokova' in EFTA files and summarize connections",
  label: "drokova-research",
  context: "Focus on Russian intelligence angles",
  timeout_secs: 1800
)
```

### 2. `task_status` / `task_list`
Check status of background tasks.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task_id` | string | | Specific task to check |
| `label` | string | | Find task by label |
| `active_only` | bool | | Only show running tasks (default: false) |
| `limit` | u32 | | Max tasks to return (default: 10) |

**Returns:**
```json
{
  "tasks": [
    {
      "task_id": "550e8400-...",
      "label": "drokova-research",
      "status": "running",
      "started_at": "2026-02-21T08:30:00Z",
      "elapsed_secs": 142,
      "model": "claude-sonnet-4",
      "progress": "Searched 47 documents, found 12 mentions..."
    }
  ]
}
```

### 3. `task_join`
Wait for task completion and retrieve results.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task_id` | string | * | Task to join (one required) |
| `label` | string | * | Or find by label |
| `timeout_ms` | u64 | | Max wait time (default: 30000) |

**Returns:**
```json
{
  "task_id": "550e8400-...",
  "status": "completed",
  "result": "Found 12 Drokova mentions across 8 documents...",
  "artifacts": [
    {"type": "file", "path": "research/drokova-summary.md"}
  ],
  "usage": {
    "input_tokens": 45000,
    "output_tokens": 3200,
    "cost_usd": 0.12
  }
}
```

### 4. `task_kill`
Terminate a running task.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task_id` | string | * | Task to kill (one required) |
| `label` | string | * | Or find by label |
| `reason` | string | | Why it's being killed |

**Returns:**
```json
{
  "task_id": "550e8400-...",
  "status": "killed",
  "partial_result": "Searched 23 documents before termination..."
}
```

### 5. `task_steer`
Send additional instructions to a running task.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `task_id` | string | * | Task to steer |
| `label` | string | * | Or find by label |
| `message` | string | ✓ | Instruction to inject |

**Example:**
```
task_steer(label: "drokova-research", message: "Also check for 'Day One Ventures' references")
```

## Architecture

### Task Runner (Rust)

```
┌─────────────────────────────────────────────────────────┐
│                      Gateway                             │
│  ┌─────────────┐    ┌─────────────────────────────────┐ │
│  │ Main Session│    │         Task Manager            │ │
│  │             │───▶│  ┌─────┐ ┌─────┐ ┌─────┐       │ │
│  │  (chat)     │    │  │Task1│ │Task2│ │Task3│       │ │
│  └─────────────┘    │  └─────┘ └─────┘ └─────┘       │ │
│                     │     ▼       ▼       ▼          │ │
│                     │  ┌─────────────────────────┐   │ │
│                     │  │   Tokio Task Pool       │   │ │
│                     │  │   (async executors)     │   │ │
│                     │  └─────────────────────────┘   │ │
│                     └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Key Components

1. **TaskManager** (`src/tasks/manager.rs`)
   - Owns all background tasks for a gateway instance
   - Maps task_id → TaskHandle
   - Enforces limits (max concurrent, per-session quotas)

2. **Task** (`src/tasks/task.rs`)
   - Isolated execution context
   - Own message history (not shared with parent)
   - Can use same tools as main session (configurable)
   - Progress reporting via channel

3. **TaskHandle**
   - Lightweight reference to running task
   - Used for status checks, steering, killing
   - Contains oneshot channel for completion notification

### Data Structures

```rust
pub struct Task {
    id: TaskId,
    label: Option<String>,
    parent_session: SessionKey,
    status: TaskStatus,
    
    // Execution
    model: ModelConfig,
    messages: Vec<Message>,
    tools: ToolSet,  // inherited or restricted from parent
    
    // Lifecycle
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    timeout: Duration,
    
    // Communication
    progress_tx: mpsc::Sender<ProgressUpdate>,
    steer_rx: mpsc::Receiver<String>,
    result: Option<TaskResult>,
}

pub enum TaskStatus {
    Spawned,
    Running,
    Completed,
    Failed(String),
    Killed(String),
    Timeout,
}

pub struct TaskResult {
    output: String,
    artifacts: Vec<Artifact>,
    usage: TokenUsage,
}
```

### Concurrency Model

- Tasks run as Tokio tasks (not OS threads)
- Non-blocking — main session continues while tasks run
- Shared rate limiter with main session (configurable)
- Default: max 5 concurrent tasks per session

### Context Isolation

Tasks get:
- ✅ Own message history (fresh start with system prompt + task instruction)
- ✅ Access to filesystem (same workspace)
- ✅ Access to tools (configurable subset)
- ✅ Own memory context (can read MEMORY.md, write to task-specific logs)
- ❌ No access to parent's conversation history (unless explicitly passed)
- ❌ No access to parent's secrets (unless explicitly passed)

### Notification Flow

When a task completes:
1. TaskManager receives completion signal
2. If `notify: true`, sends system message to parent session
3. Parent session can then `task_join` to get full results

```
[System Message] Background task "drokova-research" completed (2m 34s).
Summary: Found 12 Drokova mentions across 8 EFTA documents.
Use task_join(label: "drokova-research") for full results.
```

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] `TaskManager` struct with spawn/list/kill
- [ ] `Task` execution loop (single turn for now)
- [ ] Basic `task_spawn` and `task_status` tools
- [ ] In-memory task storage

### Phase 2: Full Lifecycle
- [ ] Multi-turn task execution
- [ ] `task_join` with result retrieval
- [ ] `task_kill` with graceful shutdown
- [ ] Timeout handling

### Phase 3: Communication
- [ ] `task_steer` for mid-flight instructions
- [ ] Progress reporting
- [ ] Completion notifications to parent session

### Phase 4: Persistence & Polish
- [ ] Persist task state across gateway restarts
- [ ] Task logs (separate from main session)
- [ ] Resource quotas and rate limiting
- [ ] Metrics integration (Prometheus)

## Edge Cases

1. **Parent session ends while tasks running**
   - Tasks continue to completion
   - Results stored for later retrieval
   - Orphan cleanup after configurable TTL

2. **Task spawns sub-tasks**
   - Allowed (recursive spawning)
   - Depth limit (default: 3)
   - Total task limit still applies

3. **Gateway restart**
   - Phase 1-3: Tasks lost (acceptable for MVP)
   - Phase 4: Restore from persistent storage

4. **Model rate limits**
   - Tasks share rate limiter with parent
   - Optional: dedicated quota for background tasks

## Configuration

```toml
[tasks]
enabled = true
max_concurrent_per_session = 5
max_concurrent_global = 50
default_timeout_secs = 3600
max_timeout_secs = 86400
persist = false  # Phase 4
```

## Comparison with OpenClaw

| Feature | OpenClaw | RustyClaw (proposed) |
|---------|----------|---------------------|
| Spawn | `sessions_spawn` | `task_spawn` |
| List | `subagents(action=list)` | `task_status` |
| Kill | `subagents(action=kill)` | `task_kill` |
| Steer | `subagents(action=steer)` | `task_steer` |
| Join | `sessions_send` + wait | `task_join` (blocking) |
| Progress | Manual polling | Built-in progress channel |
| Persistence | Yes | Phase 4 |

Key improvements:
- Cleaner tool API (separate tools vs. action parameter)
- First-class `task_join` for synchronous result retrieval
- Built-in progress reporting
- Explicit context passing

## Open Questions

1. **Tool restrictions** — Should tasks have full tool access or a configurable subset?
2. **Memory sharing** — Can tasks write to shared MEMORY.md or only task-local files?
3. **Cost tracking** — Per-task usage vs. aggregated to parent session?
4. **Priority** — Should tasks have priority levels (low/normal/high)?

---

*Plan created: 2026-02-21*
