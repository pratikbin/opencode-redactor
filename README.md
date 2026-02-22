# OpenCode Redactor

A lightweight, native TypeScript **plugin** for [OpenCode](https://github.com/opencode-ai/opencode). It masks sensitive information (API keys, PII, credentials) and high-entropy strings **before text is sent to an LLM provider**, while keeping your local session usable.

## Features

- **Zero Dependencies:** Built using native TypeScript and Bun, ensuring fast startup and minimal footprint.
- **Hybrid Detection Engine:**
  - **Regex Matching:** Instantly identifies known patterns for AWS, GitHub, GitLab, Slack, Stripe, private keys, and emails.
  - **Entropy Analysis:** Uses Shannon entropy calculation to detect potential secrets that don't match specific regex patterns (e.g., random hex strings, passwords).
- **Reversible Token Registry:** Replaces secrets with deterministic `<REDACTED:hex14>` tokens backed by an in-memory registry. Write/edit tools automatically restore original values before execution so files are never corrupted.
- **Write Protection:** Blocks write operations that contain unresolvable redaction tokens, preventing corrupted output.
- **Comprehensive Hook Coverage:** Masks secrets at every stage — user input, tool output, LLM prompt construction, assistant completions, TUI events, and file diffs.
- **Metadata-Only Audit Logs:** Writes JSONL records without storing raw secret values.

## Installation

This plugin is designed for the OpenCode environment.

### 1. Local Project Installation

Copy the plugin into your project's `.opencode/plugins/` directory:

```bash
mkdir -p .opencode/plugins
cp opencode-redactor.ts .opencode/plugins/opencode-redactor.ts
```

Tip: during development, symlink instead of copying to avoid drift:

```bash
mkdir -p .opencode/plugins
ln -sf "$PWD/opencode-redactor.ts" .opencode/plugins/opencode-redactor.ts
```

### 2. Global Installation

To make the plugin available across all your OpenCode projects:

```bash
mkdir -p ~/.config/opencode/plugins
cp opencode-redactor.ts ~/.config/opencode/plugins/opencode-redactor.ts
```

### 3. Install via npm (recommended)

If you publish/install this plugin from npm, add it to your OpenCode config:

`opencode.json`

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-redactor@0.1.1"]
}
```

OpenCode will install/load the package and run the plugin's default export.

Note: OpenCode currently imports npm plugins via a directory path. This package includes a root `index.js` entrypoint for compatibility.

## Usage

Once installed, OpenCode loads the plugin automatically at startup.

This avoids “opportunistic tool calling” (where the model decides whether to call a tool after seeing your raw text).

## Auto-Mask Before LLM (Plugin)

This repo is an OpenCode plugin. The source file is:

- `opencode-redactor.ts` (copy/symlink into `.opencode/plugins/opencode-redactor.ts`)

If you paste a secret into chat, the plugin will redact it from the provider-bound prompt before any upstream request is made.

The plugin covers the full lifecycle through six hooks:

| Hook                                   | Purpose                                                                                                                        |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `experimental.chat.messages.transform` | Primary protection — mutates message parts in-place before the LLM request is constructed                                      |
| `chat.message`                         | Audits (and optionally masks) freshly received user parts                                                                      |
| `tool.execute.after`                   | Masks secrets in tool output (file reads, command output, etc.)                                                                |
| `tool.execute.before`                  | Restores `<REDACTED:…>` tokens to original values in write/edit tool args, blocking writes with unresolvable tokens            |
| `experimental.text.complete`           | Masks secrets in assistant completion text before rendering                                                                    |
| `event`                                | Observes `tui.prompt.append`, `tui.command.execute`, `message.part.updated`, and `session.diff` for early masking and auditing |

Implementation note: OpenCode continues using the same `messages` array variable after triggering `experimental.chat.messages.transform`, so the plugin must mutate `messages[*].parts[*]` in-place. Replacing `output.messages` with a new array will not reliably affect what is sent upstream.

By default, the plugin does not redact what is stored locally in session history (so you can paste secrets and keep working), but you can opt into local redaction via `OPENCODE_REDACTOR_MASK_LOCAL`.

### Reversible Token Format

Secrets are replaced with deterministic tokens: `<REDACTED:a1b2c3d4e5f6ab>` (14 hex characters derived from an FNV-1a-like hash of the original value). The in-memory token registry maps tokens back to original values, allowing write/edit tools to restore secrets before file operations.

## Testing (Local)

### 1) Unit tests (masking behavior)

Run the bun tests in this repo:

```bash
bun test
```

### 2) Manual end-to-end test (OpenCode plugin)

1. Ensure the plugin files are in either:
   - Project: `.opencode/plugins/`
   - Global: `~/.config/opencode/plugins/`

2. Restart OpenCode so it reloads plugins.

3. Test it out by sending a message with a fake secret:

```bash
export OPENCODE_REDACTOR_AUDIT_ENABLED=1
export OPENCODE_REDACTOR_AUDIT_PATH="$PWD/opencode-redactor.audit.jsonl"
rm -f "$OPENCODE_REDACTOR_AUDIT_PATH"

# In another terminal, watch the audit log:
# tail -f "$OPENCODE_REDACTOR_AUDIT_PATH"

echo "AKIAIOSFODNN7EXAMPLE" > secret-test.txt
opencode run "Read secret-test.txt and tell me what it contains"

# Then verify audit output:
cat "$OPENCODE_REDACTOR_AUDIT_PATH"
```

## Configuration

You can tune entropy sensitivity by editing the constants near the top of `opencode-redactor.ts`:

```typescript
const BASE64_ENTROPY_LIMIT = 4.5;
const HEX_ENTROPY_LIMIT = 3.0;
const MIN_LENGTH_FOR_ENTROPY = 16;
```

### Environment variables

These are read at runtime from the OpenCode/Bun process environment.

- `OPENCODE_REDACTOR_MASK_LOCAL` (default: `0`):
  - `0`: do not mutate persisted user message text; only redact provider-bound prompts.
  - `1`: also redact local session history (your pasted secrets will be replaced in stored messages).

### Recommended settings

If your goal is "let users paste secrets locally, but never send them to the LLM", keep the defaults (`OPENCODE_REDACTOR_MASK_LOCAL=0`). The `experimental.chat.messages.transform` hook will redact the provider-bound prompt, while write/edit operations restore original values via the token registry so files remain correct.

## Local Audit Log

By default, when masking changes output text, the plugin appends a single JSON line (JSONL) to a local audit file so you can track usage and which detectors fired.

- Default path: `~/.config/opencode/opencode-redactor.audit.jsonl`
- Disable logging: set `OPENCODE_REDACTOR_AUDIT_ENABLED=0`
- Override paths: `OPENCODE_REDACTOR_AUDIT_DIR` or `OPENCODE_REDACTOR_AUDIT_PATH`

Each audit line includes additional performance metadata:

- `hook`: which hook produced this record (`chat.message`, `experimental.chat.messages.transform`, `tool.execute.after`, `tool.execute.before`, `experimental.text.complete`, `tui.prompt.append`, `tui.command.execute`, `message.part.updated`, or `session.diff`)
- `durationMs`: time spent masking for that hook invocation
- `bytesIn` / `bytesOut`: UTF-8 byte size before/after masking
- `parts` / `partsChanged`: part-level metrics for `chat.message` and `experimental.chat.messages.transform`
- `fields` / `fieldsChanged`: string-field metrics for TUI event scans
- `toolName`: tool name for `tool.execute.after` / `tool.execute.before` when available
- `tokensFound` / `tokensRestored`: token restoration metrics for `tool.execute.before`

## Supported Patterns

This plugin is deliberately conservative: it prefers high-confidence regex matches and only applies entropy masking in limited contexts.

### Regex Detectors

When a match is found, the value is replaced with a placeholder. By default this is `<SECRET>`.
If you set `OPENCODE_REDACTOR_PLACEHOLDER=typed`, placeholders include the detector label (e.g. `<SECRET: AWSKeyDetector>`).

| Placeholder Label          | What It Detects                                                                        |
| -------------------------- | -------------------------------------------------------------------------------------- |
| `PrivateKeyDetector`       | PEM/OpenSSH/PGP private key blocks + common private key headers                        |
| `ArtifactoryDetector`      | JFrog Artifactory access tokens (AKC… / AP…)                                           |
| `AWSKeyDetector`           | AWS access key IDs (AKIA/ASIA/…) and AWS secret access keys in assignment-like context |
| `AzureStorageKeyDetector`  | Azure Storage `AccountKey=` values                                                     |
| `CloudantDetector`         | Cloudant credentials in URLs and common assignment patterns                            |
| `BasicAuthDetector`        | Basic auth in URLs (password only) and `Authorization: Basic ...` headers              |
| `DiscordBotTokenDetector`  | Discord bot tokens                                                                     |
| `GitHubTokenDetector`      | GitHub personal access tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)                 |
| `GitLabTokenDetector`      | GitLab tokens (`glpat-`, `gldt-`, `glft-`, `glsoat-`, `glrt-`)                         |
| `IbmCloudIamDetector`      | IBM Cloud IAM API keys in assignment-like context                                      |
| `IbmCosHmacDetector`       | IBM COS HMAC secret access keys in assignment-like context                             |
| `MailchimpDetector`        | Mailchimp API keys (`<32 hex>-us<region>`)                                             |
| `NpmDetector`              | npm auth tokens in `.npmrc`-style `_authToken=` lines                                  |
| `OpenAIDetector`           | OpenAI API keys (both current structured and legacy `sk-` formats)                     |
| `PypiTokenDetector`        | PyPI tokens (`pypi-AgEI...` / `pypi-AgEN...`)                                          |
| `SendGridDetector`         | SendGrid API keys (`SG.<...>.<...>`)                                                   |
| `SlackDetector`            | Slack tokens (`xox...`) and Slack webhook URLs                                         |
| `SoftlayerDetector`        | SoftLayer API keys in assignments and in SOAP API URLs                                 |
| `SquareOAuthDetector`      | Square OAuth secrets (`sq0csp-...`)                                                    |
| `StripeDetector`           | Stripe secret keys (`sk_live_...`, `sk_test_...`)                                      |
| `TelegramBotTokenDetector` | Telegram bot tokens (`<digits>:<35 chars>`)                                            |
| `TwilioKeyDetector`        | Twilio Account SIDs (`AC...`) and API keys (`SK...`)                                   |
| `MailDetector`             | Email addresses (PII)                                                                  |

### Content-Aware Detectors

These are not simple regex replacements across all text; they apply only in constrained contexts.

| Placeholder Label         | What It Detects                                                                  | Notes                                                                                    |
| ------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `KeywordDetector`         | Values adjacent to common secret keywords (`password`, `token`, `api_key`, etc.) | Masks the value portion of `key = value` / `key: "value"` / `password is value` patterns |
| `JwtTokenDetector`        | JWT-like tokens                                                                  | Only masked if base64url decoding succeeds and header/payload parse as JSON              |
| `HexHighEntropyString`    | High-entropy hex strings                                                         | Only masked when quoted, or when keyword context appears nearby                          |
| `Base64HighEntropyString` | High-entropy base64/base64url-ish strings                                        | Only masked when quoted, or when keyword context appears nearby                          |
