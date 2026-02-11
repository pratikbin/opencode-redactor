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

- `chat.message`: masks new user text parts before they are written to the session (prevents user-pasted secrets from being stored/sent).
- `tool.execute.after`: masks tool outputs after execution (covers secrets introduced by file reads and command output).

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

1.  **Regex Pass:** The tool first scans for high-confidence patterns (AWS, Stripe, etc.) and replaces them with `<SECRET: Type>`.
2.  **Entropy Pass:** It tokenizes the _remaining_ text (splitting by whitespace).
    - It cleans tokens of wrapping characters (quotes, brackets).
    - It ignores tokens that are already masked.
    - It calculates Shannon entropy. If > 4.5 and length > 16, it replaces with `<SECRET: HighEntropyString>`.

## Local Audit Log

The tool appends a single JSON line when masking changes output text (no secret values; metadata only).

- Default: `~/.config/opencode/opencode-redactor.audit.jsonl`
- Disable: `OPENCODE_REDACTOR_AUDIT_ENABLED=0`
- Override: `OPENCODE_REDACTOR_AUDIT_DIR` / `OPENCODE_REDACTOR_AUDIT_PATH`

Audit records include:

- `hook`, `durationMs`, `bytesIn`, `bytesOut`
- `parts`, `partsChanged` for `chat.message`
- `toolName` for `tool.execute.after` when available
