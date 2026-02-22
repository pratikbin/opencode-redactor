# CLAUDE.md

## Project Overview

`opencode-redactor` is an OpenCode plugin designed to sanitize user text by masking secrets (API keys, PII) before they are sent to LLM providers. It uses a combination of Regex patterns and Shannon Entropy analysis.

## Architecture

- **Runtime:** Bun (TypeScript)
- **Framework:** OpenCode plugin hooks (via default export).
- **Dependency Policy:** Zero external npm dependencies at runtime. Uses native JS/TS features and Bun built-ins only.
- **Key Files:**
  - `opencode-redactor.ts` contains both the plugin hooks and masking logic (single-file plugin). This file is intended to be copied/symlinked into a project's `.opencode/plugins/` directory.
  - `index.js` is the npm package root entrypoint and forwards to `dist/opencode-redactor.js` for directory import compatibility.
  - `index.d.ts` provides package-level types for TypeScript consumers.
  - `package.json` provides npm publish metadata and build scripts.

## Hook Coverage

- `experimental.chat.messages.transform`: primary protection; redacts provider-bound message history immediately before the LLM request is constructed.
  - Important: this hook must mutate `messages[*].parts[*]` in-place. OpenCode does not reliably use a replaced `output.messages` array.
- `chat.message`: optional local redaction and auditing of freshly received user parts.
  - Local persistence masking is controlled by `OPENCODE_REDACTOR_MASK_LOCAL` (default: fail-open; do not mutate stored parts).
- `tool.execute.after`: masks secrets in tool outputs after execution (file reads, command output, etc.). Also masks `output.metadata` for edit tools.
- `tool.execute.before`: restores `<REDACTED:hex14>` tokens to original values in write/edit tool args before execution. Throws a safety error if tokens cannot be resolved (prevents corrupted file writes).
- `experimental.text.complete`: masks secrets in assistant completion text before it is rendered or persisted.
- `event`: intercepts multiple event types:
  - `message.part.updated`: masks completed tool-part output/metadata before it enters conversation history and TUI rendering.
  - `session.diff`: masks `before`/`after` strings in file diffs shown in the diff viewer.
  - `tui.prompt.append`, `tui.command.execute`: observed for early detection/auditing only (no mutation).

## Development & Testing

doc: <https://github.com/anomalyco/opencode/blob/dev/packages/web/src/content/docs/plugins.mdx>

### Commands

Since this is a single-file plugin, there is no framework build step beyond `bun build`.

- **Run Tests:**

  ```bash
  bun test
  ```

- **Build (for npm publish):**
  ```bash
  bun run build
  ```

### Code Style Guidelines

- **Imports:** avoid runtime imports; keep the plugin self-contained.
- **Regex:** Keep `DETECTORS` conservative and prefer high-confidence patterns.
- **Formatting:** Standard TypeScript formatting.
- **Safety:**
  - Do not log the _original_ secrets in debug output if possible.
  - When modifying entropy logic, test against "normal" English text to ensure low false-positive rates.

## Logic Explainer

### Token Registry (Reversible Masking)

Secrets are replaced with deterministic `<REDACTED:hex14>` tokens. The token ID is derived from a dual FNV-1a-like 32-bit hash of the original value, producing 14 hex characters (56 bits). The in-memory `tokenRegistry` maps both directions: `value → token` and `token → value`. Same secret always produces the same token within a session.

`tool.execute.before` calls `unmaskArgs()` to restore tokens in write/edit tool arguments before the file operation runs. If an unresolvable token is found, it throws to prevent corrupted output.

### Detection Pipeline (`maskSecrets`)

1.  **Regex Pass:** Scans for high-confidence patterns (AWS, Stripe, GitHub, etc.) and replaces matches with `<REDACTED:hex14>` tokens.
2.  **KeywordDetector Pass:** Matches `key = "value"` / `key: value` / `password is value` patterns around known secret keywords; masks the value portion only.
3.  **JWT Pass:** Validates JWT-like tokens by base64url-decoding and JSON-parsing the header and payload; masks only formally valid JWTs.
4.  **Entropy Pass (quoted):** Any quoted string ≥ 20 chars is tested against hex and base64 entropy thresholds.
5.  **Entropy Pass (context-aware):** Unquoted tokens within 60 characters of a secret keyword are tested against entropy thresholds.

## Local Audit Log

The tool appends a single JSON line when masking changes output text (no secret values; metadata only).

- Default: `~/.config/opencode/opencode-redactor.audit.jsonl`
- Disable: `OPENCODE_REDACTOR_AUDIT_ENABLED=0`
- Override: `OPENCODE_REDACTOR_AUDIT_DIR` / `OPENCODE_REDACTOR_AUDIT_PATH`

Audit records include:

- `hook`, `durationMs`, `bytesIn`, `bytesOut`
- `parts`, `partsChanged` for `chat.message` and `experimental.chat.messages.transform`
- `fields`, `fieldsChanged` for TUI event scans
- `toolName` for `tool.execute.after` / `tool.execute.before` when available
- `tokensFound`, `tokensRestored` for `tool.execute.before`

Always test test1.sh and test2.sh and analyze it's output
