# CLAUDE.md

## Project Overview
`oc-secret-mask` is an OpenCode plugin designed to sanitize user text by masking secrets (API keys, PII) before they are sent to LLM providers. It uses a combination of Regex patterns and Shannon Entropy analysis.

## Architecture
- **Runtime:** Bun (TypeScript)
- **Framework:** `@opencode-ai/plugin` plugin hooks.
- **Dependency Policy:** Zero external npm dependencies. Uses native JS/TS features and Bun built-ins only.
- **Key Files:**
  - `secret-masker.ts` contains both the plugin hooks and masking logic (single-file plugin). This file is intended to be copied/symlinked into a project's `.opencode/plugins/` directory.

## Hook Coverage

- `chat.message`: masks new user text parts before they are written to the session (prevents user-pasted secrets from being stored/sent).
- `tool.execute.after`: masks tool outputs after execution (covers secrets introduced by file reads and command output).

## Development & Testing

doc: <https://github.com/anomalyco/opencode/blob/dev/packages/web/src/content/docs/plugins.mdx>

### Commands
Since this is a single-file plugin, there is no `package.json` build script.

- **Run Tests:**
  ```bash
  bun test
  ```

### Code Style Guidelines
- **Imports:** strict imports from `@opencode-ai/plugin`.
- **Regex:** Keep `DETECTORS` conservative and prefer high-confidence patterns.
- **Formatting:** Standard TypeScript formatting.
- **Safety:**
  - Do not log the *original* secrets in debug output if possible.
  - When modifying entropy logic, test against "normal" English text to ensure low false-positive rates.

## Logic Explainer
1.  **Regex Pass:** The tool first scans for high-confidence patterns (AWS, Stripe, etc.) and replaces them with `<SECRET: Type>`.
2.  **Entropy Pass:** It tokenizes the *remaining* text (splitting by whitespace).
    - It cleans tokens of wrapping characters (quotes, brackets).
    - It ignores tokens that are already masked.
    - It calculates Shannon entropy. If > 4.5 and length > 16, it replaces with `<SECRET: HighEntropyString>`.

## Local Audit Log

The tool appends a single JSON line per execution to a global audit file (no secret values; metadata only).

- Default: `~/.config/opencode/secret-masker.audit.jsonl`
- Disable: `SECRET_MASKER_AUDIT_ENABLED=0`
- Override: `SECRET_MASKER_AUDIT_DIR` / `SECRET_MASKER_AUDIT_PATH`
