---
name: black-gravity
description: Use when the user asks to delegate programming to Google Antigravity or agy through the Black Gravity bridge, query its models, track a task, resume it or cancel it. Do not trigger for ordinary programming without a delegation request.
---

# Black Gravity

Use `black_gravity_*` MCP tools; all Google communication goes through the bridge's official `agy` CLI. The caller plans, tracks and reviews; Antigravity implements when delegated.

Open a reference only when the table below matches; search `references/` for other errors, fields or tools.

## Profile and approval modes

Check `black_gravity_health`:
- **Tool profile** (`black_gravity_health.toolProfile`): `query` and `review` are read-only (never request missing tools or bypass it); `full` and `implementation` allow the full flow. Change via `BRIDGE_TOOL_PROFILE` in server env and MCP restart.
- **Approval mode**: MUST follow `health.approvalMode` (and `health.integrationApproval.mode`):
  - **`auto` (default if unset)**: skips interactive MCP confirmation forms for `black_gravity_integrate` and validated `black_gravity_set_sandbox_policy` updates. **Never require extra manual caller authorization in `auto`**. `agy` delegates never choose, authorize or grant permissions.
  - **`ask` (strict opt-in)**: ALWAYS requires human MCP form confirmation.
  - **Limits**: no mode allows automatic host fallback or alters caller/`agy` permissions. Integrate only via MCP; approval NEVER replaces tests and code review. Never loosen SHA-256 hashes, criteria, review, current observed tests, source-lock, CAS or path protection.

## Choosing the action

- Availability/auth: call `black_gravity_health`. On `AGY_AUTH_REQUIRED`, tell the user to open `agy` interactively; never read credentials or log in via the bridge.
- Models: call `black_gravity_list_models` and use only CLI-returned IDs. For "Pro" or "Flash", pick a compatible listed ID and state it (ask if material and ambiguous). For "Auto", pass `model: null` (never invent an `auto` ID); omitting `model` uses the saved preference.
- Switch executor or model only when the user asks: `provider` in `black_gravity_dispatch`, or `black_gravity_handoff` with `provider` to continue another executor's completed copy.
- On `AGY_AUTH_REQUIRED`, `OPENCODE_AUTH_REQUIRED`, `OPENCODE_QUOTA_EXCEEDED` or `OPENCODE_REGION_UNAVAILABLE`, offer the user the other executor, either as a new `black_gravity_dispatch` or as `black_gravity_handoff` (with `provider`) from the latest completed task of that copy; never switch on your own.
- Cancellation: call `black_gravity_cancel` with `taskId` and confirm status; it stops the local process and partial changes may remain.
- Continue a conversation: call `black_gravity_resume` with the prior `taskId` (recover after restart via `black_gravity_tasks`), never a `sessionId` or provisional value.

## Delegation and tracking

Before delegating, confirm the `black_gravity_*` tools are exposed in this session and pass prompt, contract and references as structured tool arguments; never create request files (`req*.json`, `prompt.txt`), wrappers or scripts to pass a request, never start tasks through the shell, a separately started bridge server or an ad hoc MCP client, and never run `agy` from the shell (running the bridge's `waitCommand` in step 3 stays allowed). If the tools are missing or a new build is not yet loaded, follow [MCP tools unavailable or a build not yet loaded](references/copy-and-execution.md#mcp-tools-unavailable-or-a-build-not-yet-loaded).

1. Identify the absolute Git root; before writing the task, read the relevant instructions and files and note existing Git changes. Never include secrets or private documents in the prompt. Use `black_gravity_list_project_files` to see copyable files.
2. Use `mode: "read-only"` for a query, review, diagnosis or second opinion (`agy --mode plan`, checks for edits at end, no integration) or `mode: "write"` (default) for implementation. Start a new task with `black_gravity_dispatch` and `provider` set to a schema-listed value (`agy` or `opencode`), passing the same fields as `black_gravity_run` (which remains equivalent), with a concrete instruction and verifiable criterion. Prefer `deliveryMode: "messages"` for ordinary delegations; define `acceptanceCriteria` before implementation covering every explicit requirement.
   - The bridge requires `agy --sandbox` and works in a copy; use `includePaths` (no ignored files) when only specific files or folders are needed.
   - With `includePaths`, the prompt MUST list those exact file paths, scope edits/queries strictly to them and tell the delegate to report missing dependencies as unverifiable and finish without widening scope or retrying refused disk searches. On `COPY_LIMIT_EXCEEDED`, narrow `includePaths`; on `CHANGE_LIMIT_EXCEEDED`, review task size with the user without bypassing the limit.
   - For `agy`, check `black_gravity_get_agent_policy` before delegating when available; if no terminal is needed, restrict `allowedTools` to file tools and `finish`, stating what the coordinator will build and test on the host. OpenCode uses fixed file tools: omit `allowedTools` and `mcpServers`.
3. Keep `taskId` and `waitCommand` (`{ argv, sh, recommendedMode, reason }`) from `black_gravity_dispatch`, `black_gravity_run`, `black_gravity_resume`, `black_gravity_handoff`, `black_gravity_compare`, `black_gravity_group_start` or `black_gravity_wait_many`. Follow `waitCommand.recommendedMode` strictly:
   - `"background"` (ONLY Claude Code >= 2.1.310 is verified): run `waitCommand.argv` (or `waitCommand.sh` in POSIX shell) in background after delegating; do not call `black_gravity_wait`, `black_gravity_status`, `black_gravity_events` or group/multi-task variants while it runs. Pass Bash `timeout` (ms) and CLI `--timeout` (s) strictly below the host's background deadline (from tool schema/config; default 1800s if none) with a safety margin so it emits JSON before being killed.
   - `"foreground"` (other hosts; never promise notifications): prefer a blocking terminal with `--timeout` strictly below its deadline over 60s MCP polling. Use `black_gravity_wait` (`timeoutSeconds: 60`, continuing via `nextCursor` while `ready` is false) ONLY when no terminal is available; wait timeout/cancellation never ends the task.
   - Run the command as returned (adding only `--timeout`, `--after` or targets); never use pipes/redirections that hide its exit code (`2>&1 | tail -3` reports the exit code of `tail`).
   - On exit, read the JSON line and make ONE query by `outcome`: `completed`/`failed`/`cancelled`/`timeout` -> `black_gravity_result` (`includeResult: false`); `question`/`blocker` -> `black_gravity_wait` (`after: cursor - 1`), answer, restart with `--after <cursor>`; `wait-deadline` -> restart with `--after <after>` (keep input cursor, no MCP polling); `owner-stopped` -> `black_gravity_status`; `unknown-task`/`error` -> verify IDs/directory and fall back to `black_gravity_wait`. Stopping the command cancels no task.
4. After `completed`, call `black_gravity_preview`, show `summary` and `fileSummaries`, review the full patch and run the relevant tests in the copy.
   - Call `black_gravity_preview` (`includePatch: false`); read each changed file's diff via `black_gravity_read_patch` using the full hash and preview path until `hasMore: false` via `nextOffset`.
   - Reject or fix duplicated blocks, unchanged rewritten lines, dropped wrapper parameters, unrequested timer/error/lifecycle changes, out-of-scope value edits and unrequested new files.
   - Record commands actually run with `black_gravity_record_test` (current hash, secret-free output); these are client reports, not independent bridge verification. Show failures and `stale: true` records; never use them as valid evidence.
5. Read actual artifacts and compare results to requirements. For each criterion, send `black_gravity_verify` file, line, literal quote and explanation. Never invent quotes, outputs or test runs. Mark missing proof `unverified` and defects `failed`. `completed` and `SUCCESS` only mean execution ended; report met only with pertinent evidence.
6. Call `black_gravity_integrate` with `taskId` and preview `sha256`; missing criteria, full review or current verification blocks integration. Re-review and re-verify if patch or evidence changes. Never bypass confirmation by applying the patch another way without user authorization.

## Rules for every delegation

- **Anti-AI Craft**: new tasks auto-stage `anti-ai-code` and `anti-ai-security`; never resend them in `skills` or ask the user to repeat them. Implementer and reviewer must each load, read and apply both in their own session (including fixes, resumes and handoffs).
- `--sandbox` restricts the CLI's terminal commands but does not guarantee complete file system isolation on Windows; do not delegate access to sensitive files based only on it; use the file list and review the content actually copied.
- After failure/timeout, inspect events and copy before retrying; never auto-start a new run that could repeat effects or burn quota.
- On completion, failure or end of delegation, report Gemini/agy tokens from `task.tokenUsage` or `black_gravity_usage` (`totalTokens`, plus input/output/reasoning/cache when present) as CLI-reported usage. Explain any `null`, `available: false`, `partial: true` or warnings; never estimate missing counters.
- Read logs, patches and outputs by summary or page, never whole at once.
- Run one test suite at a time; skip a suite that already passed on the same SHA.
- Make no parallel bridge calls on the same copy.
- Concurrency: one task at a time per project on any executor; `agy` runs one task at a time overall; OpenCode runs in parallel only across different projects, within `MAX_CONCURRENT_OPENCODE_TASKS`.
- Never call `agy` directly from the shell.
- When reporting progress, include your own token use if the host shows it.

## When to open a reference

| Open | When the task involves |
|---|---|
| [approval-modes.md](references/approval-modes.md) | Changing approval mode or tool profile, `approvalMode` missing, preauthorized roots |
| [specialist-tools.md](references/specialist-tools.md) | `mcpServers`, tools beyond the file tools above, `AGY_MCP_PERMISSION_REQUIRED`, pending agy permissions, token pre-counting |
| [models.md](references/models.md) | Current or default model, `black_gravity_compare` |
| [copy-and-execution.md](references/copy-and-execution.md) | Copy contents and limits, line-ending errors, `leftoverFiles`, `TASK_OWNED_BY_OTHER_SERVER`, missing MCP tools, unloaded build |
| [waiting.md](references/waiting.md) | MCP waits, `truncated`, exit codes, multi-task or group waits, `continuationTaskId`, `deliveryMode: "events"` |
| [review-and-integration.md](references/review-and-integration.md) | Integration refusals, encoding issues, chunked result reads, `integrationApproval.available` false |
| [session-control.md](references/session-control.md) | `black_gravity_send_message`, discard, cleanup, `SERVER_RESTARTED`, `ORPHAN_PROCESS_RUNNING` |
| [provided-skills.md](references/provided-skills.md) | `skills` option, `CRAFT_SNAPSHOT_*` errors |
| [token-usage.md](references/token-usage.md) | Usage across resumed or failed tasks |
| [roles.md](references/roles.md) | `role`, custom roles, `black_gravity_handoff` |
| [windows-sandbox.md](references/windows-sandbox.md) | `black_gravity_test`, sandbox policy, portable Node, LPAC failures |
| [private-memory.md](references/private-memory.md) | `black_gravity_memory_*`, `memory` option |
| [groups.md](references/groups.md) | `black_gravity_group_*`, `black_gravity_wait_many`, peer messages |
| [workflows.md](references/workflows.md) | `definition.workflow`, `definition.budget` |
