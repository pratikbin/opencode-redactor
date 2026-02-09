import type { Plugin } from "@opencode-ai/plugin";

// NOTE: User requirement: "if you can't detect don't mask it".
// This implementation prioritizes high-confidence regex detectors and
// limits entropy masking to (a) quoted strings and (b) keyword-adjacent context.

// --- Configuration ---

const SECRET_CONTEXT_KEYWORDS = [
  "api_key",
  "apikey",
  "access_key",
  "secret_access_key",
  "client_secret",
  "token",
  "secret",
  "password",
  "passwd",
  "pwd",
  "auth",
  "authorization",
  "bearer",
  "accountkey",
];

const KEYWORD_LOOKBEHIND_DISTANCE = 60;

// Entropy limits chosen to mirror Yelp/detect-secrets defaults.
const BASE64_ENTROPY_LIMIT = 4.5;
const HEX_ENTROPY_LIMIT = 3.0;
const MIN_LENGTH_FOR_ENTROPY = 16;

// --- Helpers ---

function looksLikeAlreadyMasked(input: string): boolean {
  return input.includes("<SECRET:");
}

function mask(label: string): string {
  return `<SECRET: ${label}>`;
}

type MaskReport = {
  triggered: boolean;
  countsByLabel: Record<string, number>;
};

function bump(report: MaskReport | null, label: string): void {
  if (!report) return;
  report.countsByLabel[label] = (report.countsByLabel[label] || 0) + 1;
}

function sumCounts(countsByLabel: Record<string, number>): number {
  let total = 0;
  for (const k in countsByLabel) total += countsByLabel[k] || 0;
  return total;
}

function envString(env: Record<string, unknown>, key: string): string | undefined {
  const v = env[key];
  if (typeof v !== "string") return undefined;
  return v;
}

function envTruthy(env: Record<string, unknown>, key: string, defaultValue: boolean): boolean {
  const raw = envString(env, key);
  if (raw == null) return defaultValue;
  const v = raw.trim().toLowerCase();
  if (v === "1" || v === "true" || v === "yes" || v === "on") return true;
  if (v === "0" || v === "false" || v === "no" || v === "off") return false;
  return defaultValue;
}

async function appendAuditLog(report: MaskReport): Promise<void> {
  // Best-effort local audit logging. Never throw from here.
  try {
    const BunAny = (globalThis as any).Bun;
    if (!BunAny || typeof BunAny.spawn !== "function") return;

    const env: Record<string, unknown> =
      (BunAny && typeof BunAny.env === "object" && BunAny.env) ||
      ((globalThis as any).process && (globalThis as any).process.env) ||
      {};

    if (!envTruthy(env, "SECRET_MASKER_AUDIT_ENABLED", true)) return;

    const home = envString(env, "HOME") || envString(env, "USERPROFILE");
    if (!home) return;

    const auditDir = envString(env, "SECRET_MASKER_AUDIT_DIR") || `${home}/.config/opencode`;
    const auditPath = envString(env, "SECRET_MASKER_AUDIT_PATH") || `${auditDir}/secret-masker.audit.jsonl`;

    const payload = {
      ts: new Date().toISOString(),
      tool: "secret-masker",
      triggered: report.triggered,
      totalMatches: sumCounts(report.countsByLabel),
      countsByLabel: report.countsByLabel,
    };
    const line = `${JSON.stringify(payload)}\n`;
    const bytes = new TextEncoder().encode(line);

    const tryAppend = async (): Promise<boolean> => {
      const proc = BunAny.spawn(["tee", "-a", auditPath], {
        stdin: bytes,
        stdout: "ignore",
        stderr: "ignore",
      });
      const code = await proc.exited;
      return code === 0;
    };

    // Fast path: append directly (one process) when the directory exists.
    if (await tryAppend()) return;

    // If the directory doesn't exist, create it and retry once.
    const mkdir = BunAny.spawn(["mkdir", "-p", auditDir], { stdout: "ignore", stderr: "ignore" });
    await mkdir.exited;
    await tryAppend();
  } catch {
    // Intentionally ignore audit logging failures.
  }
}

function calculateShannonEntropy(data: string): number {
  const len = data.length;
  if (len === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const c = data[i];
    frequencies[c] = (frequencies[c] || 0) + 1;
  }

  let entropy = 0;
  for (const c in frequencies) {
    const p = frequencies[c] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function calculateHexEntropyAdjusted(data: string): number {
  // Mirrors detect-secrets heuristic: digit-only "hex" strings are a common source of false positives.
  let entropy = calculateShannonEntropy(data);
  if (data.length <= 1) return entropy;

  if (/^\d+$/.test(data)) {
    entropy -= 1.2 / Math.log2(data.length);
  }

  return entropy;
}

function hasKeywordContext(textBefore: string): boolean {
  const window = textBefore.slice(-KEYWORD_LOOKBEHIND_DISTANCE).toLowerCase();
  return SECRET_CONTEXT_KEYWORDS.some((kw) => window.includes(kw));
}

function base64EntropyPasses(token: string): boolean {
  if (token.length < 20) return false;
  if (!/^[A-Za-z0-9+/\-_]+=*$/.test(token)) return false;
  return calculateShannonEntropy(token) > BASE64_ENTROPY_LIMIT;
}

function hexEntropyPasses(token: string): boolean {
  if (token.length < 20) return false;
  if (!/^[A-Fa-f0-9]+$/.test(token)) return false;
  return calculateHexEntropyAdjusted(token) > HEX_ENTROPY_LIMIT;
}

function b64UrlDecodeToString(input: string): string | null {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const m = b64.length % 4;
  if (m === 1) return null;
  if (m === 2) b64 += "==";
  if (m === 3) b64 += "=";

  try {
    // atob returns a "binary string" (bytes 0-255 in each code unit)
    // Use TextDecoder to decode those bytes as UTF-8.
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return null;
  }
}

function isJwtFormallyValid(token: string): boolean {
  // Ported behaviorally from Yelp/detect-secrets JwtTokenDetector.
  const parts = token.split(".");
  if (parts.length < 2 || parts.length > 3) return false;

  for (let i = 0; i < parts.length; i++) {
    const decoded = b64UrlDecodeToString(parts[i]);
    if (decoded == null) return false;

    if (i < 2) {
      try {
        JSON.parse(decoded);
      } catch {
        return false;
      }
    }
  }

  return true;
}

type Detector = {
  label: string;
  regex: RegExp;
  replacer: (...args: any[]) => string;
};

// --- Detectors (regex-first) ---

const DETECTORS: Detector[] = [
  // Private keys (mask full block)
  {
    label: "PrivateKeyDetector",
    regex:
      /-----BEGIN (?:DSA |EC |OPENSSH |PGP |RSA |SSH2 ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:DSA |EC |OPENSSH |PGP |RSA |SSH2 ENCRYPTED )?PRIVATE KEY-----/g,
    replacer: () => mask("PrivateKeyDetector"),
  },
  // Private key headers (fallback)
  {
    label: "PrivateKeyDetector",
    regex:
      /(BEGIN DSA PRIVATE KEY|BEGIN EC PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|BEGIN PRIVATE KEY|BEGIN RSA PRIVATE KEY|BEGIN SSH2 ENCRYPTED PRIVATE KEY|PuTTY-User-Key-File-2)/g,
    replacer: () => mask("PrivateKeyDetector"),
  },

  // Artifactory (from detect-secrets)
  {
    label: "ArtifactoryDetector",
    regex: /(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}(?:\s|"|$|[\]\)\}\.,;])/g,
    replacer: () => mask("ArtifactoryDetector"),
  },
  {
    label: "ArtifactoryDetector",
    regex: /(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|"|$|[\]\)\}\.,;])/g,
    replacer: () => mask("ArtifactoryDetector"),
  },

  // AWS (from detect-secrets)
  {
    label: "AWSKeyDetector",
    regex: /(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}/g,
    replacer: () => mask("AWSKeyDetector"),
  },
  {
    label: "AWSKeyDetector",
    regex: /(aws.{0,20}?(?:key|pwd|pw|password|pass|token).{0,20}?[\'\"])([0-9a-zA-Z/+]{40})([\'\"])/gi,
    replacer: (_m: string, p1: string, _secret: string, p3: string) => `${p1}${mask("AWSKeyDetector")}${p3}`,
  },

  // Azure storage account key (from detect-secrets)
  {
    label: "AzureStorageKeyDetector",
    regex: /(AccountKey=)([a-zA-Z0-9+/=]{88})/g,
    replacer: (_m: string, p1: string) => `${p1}${mask("AzureStorageKeyDetector")}`,
  },

  // Cloudant URL (subset of detect-secrets)
  {
    label: "CloudantDetector",
    regex: /(https?:\/\/)([\w\-]+:)([0-9a-f]{64}|[a-z]{24})(@[\w\-]+\.cloudant\.com)/gi,
    replacer: (_m: string, p1: string, p2: string, _secret: string, p4: string) => `${p1}${p2}${mask("CloudantDetector")}${p4}`,
  },
  // Cloudant assignments (subset)
  {
    label: "CloudantDetector",
    regex: /(\b(?:cloudant|cl|clou)(?:api|)?(?:key|pwd|pw|password|pass|token)\b\s*[:=]\s*)([0-9a-f]{64}|[a-z]{24})\b/gi,
    replacer: (_m: string, p1: string) => `${p1}${mask("CloudantDetector")}`,
  },

  // Basic auth in URL (from detect-secrets) - mask password only
  {
    label: "BasicAuthDetector",
    regex: /:\/\/([^:\/\?#\[\]@\s!$&'()*+,;=]+:)([^:\/\?#\[\]@\s!$&'()*+,;=]+)(@)/g,
    replacer: (_m: string, p1: string, _pw: string, p3: string) => `://${p1}${mask("BasicAuthDetector")}${p3}`,
  },

  // Basic auth header
  {
    label: "BasicAuthDetector",
    regex: /(\bBasic\s+)([A-Za-z0-9+/=]{20,})/g,
    replacer: (_m: string, p1: string) => `${p1}${mask("BasicAuthDetector")}`,
  },

  // Discord
  {
    label: "DiscordBotTokenDetector",
    regex: /[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}/g,
    replacer: () => mask("DiscordBotTokenDetector"),
  },

  // GitHub
  {
    label: "GitHubTokenDetector",
    regex: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}/g,
    replacer: () => mask("GitHubTokenDetector"),
  },

  // GitLab (common prefixes)
  {
    label: "GitLabTokenDetector",
    regex: /(glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_\-]{20,50}(?!\w)/g,
    replacer: () => mask("GitLabTokenDetector"),
  },

  // IBM Cloud IAM (assignment-focused, from detect-secrets)
  {
    label: "IbmCloudIamDetector",
    regex:
      /(\b(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)?(?:_|-|)?(?:api)?(?:_|-|)?(?:key|pwd|password|pass|token)\b\s*[:=]\s*)([a-zA-Z0-9_\-]{44})(?![a-zA-Z0-9_\-])/gi,
    replacer: (_m: string, p1: string) => `${p1}${mask("IbmCloudIamDetector")}`,
  },

  // IBM COS HMAC secret key (from detect-secrets)
  {
    label: "IbmCosHmacDetector",
    regex:
      /(\b(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?|)[\w\-]*secret[-_]?(?:access)?[-_]?key\b\s*[:=]\s*)([a-f0-9]{48})(?![a-f0-9])/gi,
    replacer: (_m: string, p1: string) => `${p1}${mask("IbmCosHmacDetector")}`,
  },

  // Mailchimp
  {
    label: "MailchimpDetector",
    regex: /[0-9a-z]{32}-us[0-9]{1,2}/g,
    replacer: () => mask("MailchimpDetector"),
  },

  // NPM (from detect-secrets)
  {
    label: "NpmDetector",
    regex: /(\/\/.+\/:_authToken=\s*)(npm_.+|[A-Fa-f0-9-]{36})/g,
    replacer: (_m: string, p1: string) => `${p1}${mask("NpmDetector")}`,
  },

  // OpenAI (from detect-secrets + legacy sk-48)
  {
    label: "OpenAIDetector",
    regex: /sk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
    replacer: () => mask("OpenAIDetector"),
  },
  {
    label: "OpenAIDetector",
    regex: /\bsk-[A-Za-z0-9]{48}\b/g,
    replacer: () => mask("OpenAIDetector"),
  },

  // PyPI tokens (from detect-secrets)
  {
    label: "PypiTokenDetector",
    regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}/g,
    replacer: () => mask("PypiTokenDetector"),
  },
  {
    label: "PypiTokenDetector",
    regex: /pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9-_]{70,}/g,
    replacer: () => mask("PypiTokenDetector"),
  },

  // SendGrid
  {
    label: "SendGridDetector",
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    replacer: () => mask("SendGridDetector"),
  },

  // Slack
  {
    label: "SlackDetector",
    regex: /xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+/gi,
    replacer: () => mask("SlackDetector"),
  },
  {
    label: "SlackDetector",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/gi,
    replacer: () => mask("SlackDetector"),
  },

  // SoftLayer (from detect-secrets)
  {
    label: "SoftlayerDetector",
    regex:
      /(\b(?:softlayer|sl)(?:_|-|)(?:api)?(?:_|-|)?(?:key|pwd|password|pass|token)\b\s*[:=]\s*)([a-z0-9]{64})\b/gi,
    replacer: (_m: string, p1: string) => `${p1}${mask("SoftlayerDetector")}`,
  },
  {
    label: "SoftlayerDetector",
    regex: /(?:http|https):\/\/api\.softlayer\.com\/soap\/(?:v3|v3\.1)\/([a-z0-9]{64})/gi,
    replacer: () => mask("SoftlayerDetector"),
  },

  // Square OAuth secret
  {
    label: "SquareOAuthDetector",
    regex: /sq0csp-[0-9A-Za-z\-_]{43}/g,
    replacer: () => mask("SquareOAuthDetector"),
  },

  // Stripe
  {
    label: "StripeDetector",
    regex: /(?:r|s)k_live_[0-9a-zA-Z]{24}/g,
    replacer: () => mask("StripeDetector"),
  },
  {
    label: "StripeDetector",
    regex: /(?:r|s)k_test_[0-9a-zA-Z]{24}/g,
    replacer: () => mask("StripeDetector"),
  },

  // Telegram bot token
  {
    label: "TelegramBotTokenDetector",
    regex: /\b\d{8,10}:[0-9A-Za-z_-]{35}\b/g,
    replacer: () => mask("TelegramBotTokenDetector"),
  },

  // Twilio (from detect-secrets)
  {
    label: "TwilioKeyDetector",
    regex: /\bAC[a-z0-9]{32}\b/gi,
    replacer: () => mask("TwilioKeyDetector"),
  },
  {
    label: "TwilioKeyDetector",
    regex: /\bSK[a-z0-9]{32}\b/gi,
    replacer: () => mask("TwilioKeyDetector"),
  },

  // Email (PII)
  {
    label: "MailDetector",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replacer: () => mask("MailDetector"),
  },
];

const JWT_REGEX = /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g;

// KeywordDetector: keep this conservative.
const KEYWORD_VALUE_REGEXES: RegExp[] = [
  // key: "value" / key = 'value'
  /\b\w*(api_?key|auth_?key|service_?key|account_?key|db_?pass|database_?pass|key_?pass|password|passwd|pwd|secret|token|private_?key|client_?secret)\w*\b\s*[:=]\s*([\'\"`])([^\'\"`\r\n]{4,})\2/gi,
  // key: value (unquoted)
  /\b\w*(api_?key|auth_?key|service_?key|account_?key|db_?pass|database_?pass|key_?pass|password|passwd|pwd|secret|token|private_?key|client_?secret)\w*\b\s*[:=]\s*([^\s\"\'`,;]{8,})/gi,
  // password is value
  /\b\w*(password|passwd|pwd|secret|token|api_?key)\w*\b\s+is\s+([^\s\"\'`,;]{8,})/gi,
];

function applyDetectors(input: string, report: MaskReport | null): string {
  let text = input;

  for (const d of DETECTORS) {
    text = text.replace(d.regex, (...args: any[]) => {
      const matched = String(args[0]);
      if (looksLikeAlreadyMasked(matched)) return matched;
      bump(report, d.label);
      return d.replacer(...args);
    });
  }

  // KeywordDetector pass (mask values only)
  for (const re of KEYWORD_VALUE_REGEXES) {
    text = text.replace(re, (m, _g1, g2, g3) => {
      if (looksLikeAlreadyMasked(String(m))) return String(m);

      bump(report, "KeywordDetector");

      if (g3 !== undefined) {
        return String(m).replace(String(g3), mask("KeywordDetector"));
      }

      // Unquoted / "is" regex
      const value = String(g2);
      return String(m).replace(value, mask("KeywordDetector"));
    });
  }

  // JWT validation pass (only mask if formally valid)
  text = text.replace(JWT_REGEX, (m) => {
    if (looksLikeAlreadyMasked(m)) return m;
    if (!isJwtFormallyValid(m)) return m;

    bump(report, "JwtTokenDetector");
    return mask("JwtTokenDetector");
  });

  // High entropy passes
  // 1) quoted strings (we keep this broad, but only mask if the token passes the
  // specific base64/hex entropy checks)
  text = text.replace(/([\'\"])([^\'\"\r\n]{20,})(\1)/g, (_m, q, body, q2) => {
    const token = String(body);
    if (looksLikeAlreadyMasked(token)) return `${q}${token}${q2}`;

    if (hexEntropyPasses(token)) {
      bump(report, "HexHighEntropyString");
      return `${q}${mask("HexHighEntropyString")}${q2}`;
    }
    if (base64EntropyPasses(token)) {
      bump(report, "Base64HighEntropyString");
      return `${q}${mask("Base64HighEntropyString")}${q2}`;
    }

    return `${q}${token}${q2}`;
  });

  // 2) context-aware token entropy
  text = text.replace(/\S+/g, (token: string, offset: number, fullString: string) => {
    if (looksLikeAlreadyMasked(token)) return token;

    const before = fullString.substring(0, offset);
    if (!hasKeywordContext(before)) return token;

    const clean = token.replace(/^['"(\[<{]+|['")\]>}]+$/g, "");
    if (clean.length < MIN_LENGTH_FOR_ENTROPY) return token;

    if (hexEntropyPasses(clean)) {
      bump(report, "HexHighEntropyString");
      return token.replace(clean, mask("HexHighEntropyString"));
    }
    if (base64EntropyPasses(clean)) {
      bump(report, "Base64HighEntropyString");
      return token.replace(clean, mask("Base64HighEntropyString"));
    }

    return token;
  });

  return text;
}

function maskSecrets(text: unknown): { masked: string; report: MaskReport } {
  const report: MaskReport = { triggered: false, countsByLabel: {} };
  const input = typeof text === "string" ? text : text == null ? "" : String(text);
  const masked = input ? applyDetectors(input, report) : "";
  report.triggered = sumCounts(report.countsByLabel) > 0;
  return { masked, report };
}

// --- OpenCode plugin (single-file) ---

const OpenCodeSecretMasker: Plugin = async ({ client }) => {
  await client.app.log({
    body: {
      service: "secret-masker",
      level: "info",
      message: "secret masker plugin initialized",
    },
  });

  return {
    // Mask secrets in user-pasted text before it is persisted/sent.
    "chat.message": async (_input, output) => {
      try {
        const parts = output.parts as any[];
        if (!Array.isArray(parts) || parts.length === 0) return;

        let changed = false;
        let aggregateTriggered = false;
        const aggregateCounts: Record<string, number> = {};

        const next = parts.map((part) => {
          if (!part || part.type !== "text" || typeof part.text !== "string") return part;

          const res = maskSecrets(part.text);
          aggregateTriggered = aggregateTriggered || res.report.triggered;
          for (const k in res.report.countsByLabel) {
            aggregateCounts[k] = (aggregateCounts[k] || 0) + (res.report.countsByLabel[k] || 0);
          }

          if (res.masked === part.text) return part;
          changed = true;
          return { ...part, text: res.masked };
        });

        if (!changed) return;
        output.parts = next as any;

        await appendAuditLog({ triggered: aggregateTriggered, countsByLabel: aggregateCounts });
      } catch {
        // Best-effort; never break chat.
      }
    },

    // Mask secrets introduced by tool outputs (read/grep/bash/etc).
    "tool.execute.after": async (_input, output) => {
      try {
        const raw = (output as any)?.output;
        if (typeof raw !== "string" || raw.length === 0) return;

        const res = maskSecrets(raw);
        if (res.masked === raw) return;

        (output as any).output = res.masked;
        await appendAuditLog(res.report);
      } catch {
        // Best-effort; never break tool execution.
      }
    },
  };
};

// OpenCode's plugin loader may attempt to call every exported function.
// Export a single default plugin function and attach internals for tests.
(OpenCodeSecretMasker as any).maskSecrets = maskSecrets;
(OpenCodeSecretMasker as any).appendAuditLog = appendAuditLog;

export default OpenCodeSecretMasker;
