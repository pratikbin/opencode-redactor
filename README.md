# OpenCode Redactor

A lightweight, native TypeScript **plugin** for [OpenCode](https://github.com/opencode-ai/opencode). It masks sensitive information (API keys, PII, credentials) and high-entropy strings **before text is sent to an LLM provider**.

## Features

- **Zero Dependencies:** Built using native TypeScript and Bun, ensuring fast startup and minimal footprint.
- **Hybrid Detection Engine:**
  - **Regex Matching:** Instantly identifies known patterns for AWS, GitHub, GitLab, Slack, Stripe, private keys, and emails.
  - **Entropy Analysis:** Uses Shannon entropy calculation to detect potential secrets that don't match specific regex patterns (e.g., random hex strings, passwords).
- **Smart Masking:** Replaces secrets with descriptive placeholders like `<SECRET: AWSKeyDetector>` or `<SECRET: Base64HighEntropyString>`, preserving context while hiding the original value.
- **Pre-Send Hook Coverage:** Masks both user chat text and tool output text via OpenCode hooks.
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
  "plugin": ["@pratikbin/opencode-redactor@0.1.1"]
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

If you paste a secret into chat, it should be replaced with `<SECRET: ...>` placeholders before any upstream request is made.

To also protect secrets introduced by tools (file reads, command output, etc.), the plugin hooks:

- `tool.execute.after`

This masks tool outputs at the source so they are never printed/stored/sent unmasked in subsequent model turns.

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

## Local Audit Log

By default, when masking changes output text, the plugin appends a single JSON line (JSONL) to a local audit file so you can track usage and which detectors fired.

- Default path: `~/.config/opencode/opencode-redactor.audit.jsonl`
- Disable logging: set `OPENCODE_REDACTOR_AUDIT_ENABLED=0`
- Override paths: `OPENCODE_REDACTOR_AUDIT_DIR` or `OPENCODE_REDACTOR_AUDIT_PATH`

Each audit line includes additional performance metadata:

- `hook`: `chat.message` or `tool.execute.after`
- `durationMs`: time spent masking for that hook invocation
- `bytesIn` / `bytesOut`: UTF-8 byte size before/after masking
- `parts` / `partsChanged`: part-level metrics for `chat.message`
- `toolName`: tool name for `tool.execute.after` when available

## Supported Patterns

This plugin is deliberately conservative: it prefers high-confidence regex matches and only applies entropy masking in limited contexts.

### Regex Detectors

When a match is found, the value is replaced with a placeholder like `<SECRET: AWSKeyDetector>`.

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
