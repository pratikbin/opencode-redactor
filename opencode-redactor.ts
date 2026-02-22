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

// --- Token Registry (session-scoped, reversible masking) ---

// Pure-JS synchronous hash: two independent FNV-1a-like 32-bit accumulators
// combined into 14 hex characters (56 bits). Deterministic: same input → same token.
function hashToHex14(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul((h2 << 5) ^ c ^ i, 0x5bd1e995) >>> 0;
  }
  return (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0")).slice(0, 14);
}

const tokenRegistry = {
  valueToToken: new Map<string, string>(),
  tokenToValue: new Map<string, string>(),
};

function resetTokenRegistry(): void {
  tokenRegistry.valueToToken.clear();
  tokenRegistry.tokenToValue.clear();
}

function redact(originalValue: string): string {
  const existing = tokenRegistry.valueToToken.get(originalValue);
  if (existing) return existing;

  const token = `<REDACTED:${hashToHex14(originalValue)}>`;
  tokenRegistry.valueToToken.set(originalValue, token);
  tokenRegistry.tokenToValue.set(token, originalValue);
  return token;
}

const REDACTED_TOKEN_RE = /<REDACTED:[a-f0-9]{14}>/g;

function unmaskString(text: string): string {
  return text.replace(REDACTED_TOKEN_RE, (token) => {
    return tokenRegistry.tokenToValue.get(token) ?? token;
  });
}

function unmaskArgs(args: any): any {
  if (typeof args === "string") return unmaskString(args);
  if (!args || typeof args !== "object") return args;
  if (Array.isArray(args)) return args.map(unmaskArgs);

  const result: Record<string, any> = {};
  for (const key in args) {
    result[key] = unmaskArgs(args[key]);
  }
  return result;
}

function containsUnresolvedTokens(args: any): boolean {
  const json = JSON.stringify(args);
  const matches = json.match(REDACTED_TOKEN_RE);
  if (!matches) return false;
  return matches.some((token) => !tokenRegistry.tokenToValue.has(token));
}

const WRITE_TOOL_KEYWORDS = [
  "write",
  "edit",
  "patch",
  "create",
  "save",
  "update",
  "mv",
  "rename",
  "cp",
  "copy",
];

function isWriteTool(toolName: string): boolean {
  if (!toolName) return false;
  const lower = toolName.toLowerCase();
  return WRITE_TOOL_KEYWORDS.some((kw) => lower.includes(kw));
}

function looksLikeAlreadyMasked(input: string): boolean {
  return input.includes("<SECRET") || input.includes("<REDACTED:");
}

type MaskReport = {
  triggered: boolean;
  countsByLabel: Record<string, number>;
};

type AuditMeta = {
  hook:
    | "chat.message"
    | "tool.execute.after"
    | "tool.execute.before"
    | "experimental.chat.messages.transform"
    | "experimental.text.complete"
    | "tui.prompt.append"
    | "tui.command.execute"
    | "message.part.updated"
    | "session.diff";
  durationMs: number;
  bytesIn: number;
  bytesOut?: number;
  parts?: number;
  partsChanged?: number;
  fields?: number;
  fieldsChanged?: number;
  tool?: string;
  sessionID?: string;
  messageID?: string;
  tokensFound?: number;
  tokensRestored?: number;
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

const ENV: Record<string, string | undefined> =
  (globalThis as any).Bun?.env ?? (globalThis as any).process?.env ?? {};

function envTruthy(key: string, defaultValue: boolean): boolean {
  const raw = ENV[key];
  if (raw == null) return defaultValue;
  const v = raw.trim().toLowerCase();
  if (v === "1" || v === "true" || v === "yes" || v === "on") return true;
  if (v === "0" || v === "false" || v === "no" || v === "off") return false;
  return defaultValue;
}

function nowMs(): number {
  return (globalThis as any).performance?.now?.() ?? Date.now();
}

const ENC = new TextEncoder();
function utf8ByteLength(text: string): number {
  return ENC.encode(text).length;
}

async function appendAuditLog(report: MaskReport, meta?: AuditMeta): Promise<void> {
  // Best-effort local audit logging. Never throw from here.
  try {
    const BunAny = (globalThis as any).Bun;
    if (!BunAny || typeof BunAny.spawn !== "function") return;

    if (!envTruthy("OPENCODE_REDACTOR_AUDIT_ENABLED", true)) return;

    const home = ENV["HOME"] ?? ENV["USERPROFILE"];
    if (!home) return;

    const auditDir = ENV["OPENCODE_REDACTOR_AUDIT_DIR"] ?? `${home}/.config/opencode`;
    const auditPath =
      ENV["OPENCODE_REDACTOR_AUDIT_PATH"] ?? `${auditDir}/opencode-redactor.audit.jsonl`;

    const payload: any = {
      ts: new Date().toISOString(),
      tool: "opencode-redactor",
      triggered: report.triggered,
      totalMatches: sumCounts(report.countsByLabel),
      countsByLabel: report.countsByLabel,
    };

    if (meta) {
      payload.hook = meta.hook;
      payload.durationMs = meta.durationMs;
      payload.bytesIn = meta.bytesIn;
      if (typeof meta.bytesOut === "number") payload.bytesOut = meta.bytesOut;
      if (typeof meta.parts === "number") payload.parts = meta.parts;
      if (typeof meta.partsChanged === "number") payload.partsChanged = meta.partsChanged;
      if (typeof meta.fields === "number") payload.fields = meta.fields;
      if (typeof meta.fieldsChanged === "number") payload.fieldsChanged = meta.fieldsChanged;
      if (typeof meta.tool === "string") payload.toolName = meta.tool;
      if (typeof meta.sessionID === "string") payload.sessionID = meta.sessionID;
      if (typeof meta.messageID === "string") payload.messageID = meta.messageID;
      if (typeof meta.tokensFound === "number") payload.tokensFound = meta.tokensFound;
      if (typeof meta.tokensRestored === "number") payload.tokensRestored = meta.tokensRestored;
    }
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
    replacer: (m: string) => redact(m),
  },
  // Private key headers (fallback)
  {
    label: "PrivateKeyDetector",
    regex:
      /(BEGIN DSA PRIVATE KEY|BEGIN EC PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|BEGIN PRIVATE KEY|BEGIN RSA PRIVATE KEY|BEGIN SSH2 ENCRYPTED PRIVATE KEY|PuTTY-User-Key-File-2)/g,
    replacer: (m: string) => redact(m),
  },

  // Artifactory (from detect-secrets)
  {
    label: "ArtifactoryDetector",
    regex: /(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}(?:\s|"|$|[\])}.,;])/g,
    replacer: (m: string) => redact(m),
  },
  {
    label: "ArtifactoryDetector",
    regex: /(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|"|$|[\])}.,;])/g,
    replacer: (m: string) => redact(m),
  },

  // AWS (from detect-secrets)
  {
    label: "AWSKeyDetector",
    regex: /(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}/g,
    replacer: (m: string) => redact(m),
  },
  {
    label: "AWSKeyDetector",
    regex: /(aws.{0,20}?(?:key|pwd|pw|password|pass|token).{0,20}?['"])([0-9a-zA-Z/+]{40})(['"])/gi,
    replacer: (_m: string, p1: string, secret: string, p3: string) => `${p1}${redact(secret)}${p3}`,
  },

  // Azure storage account key (from detect-secrets)
  {
    label: "AzureStorageKeyDetector",
    regex: /(AccountKey=)([a-zA-Z0-9+/=]{88})/g,
    replacer: (_m: string, p1: string, secret: string) => `${p1}${redact(secret)}`,
  },

  // Cloudant URL (subset of detect-secrets)
  {
    label: "CloudantDetector",
    regex: /(https?:\/\/)([\w-]+:)([0-9a-f]{64}|[a-z]{24})(@[\w-]+\.cloudant\.com)/gi,
    replacer: (_m: string, p1: string, p2: string, secret: string, p4: string) =>
      `${p1}${p2}${redact(secret)}${p4}`,
  },
  // Cloudant assignments (subset)
  {
    label: "CloudantDetector",
    regex:
      /(\b(?:cloudant|cl|clou)(?:api|)?(?:key|pwd|pw|password|pass|token)\b\s*[:=]\s*)([0-9a-f]{64}|[a-z]{24})\b/gi,
    replacer: (_m: string, p1: string, secret: string) => `${p1}${redact(secret)}`,
  },

  // Basic auth in URL (from detect-secrets) - mask password only
  {
    label: "BasicAuthDetector",
    regex: /:\/\/([^:/?#[\]@\s!$&'()*+,;=]+:)([^:/?#[\]@\s!$&'()*+,;=]+)(@)/g,
    replacer: (_m: string, p1: string, pw: string, p3: string) => `://${p1}${redact(pw)}${p3}`,
  },

  // Basic auth header
  {
    label: "BasicAuthDetector",
    regex: /(\bBasic\s+)([A-Za-z0-9+/=]{20,})/g,
    replacer: (_m: string, p1: string, secret: string) => `${p1}${redact(secret)}`,
  },

  // Discord
  {
    label: "DiscordBotTokenDetector",
    regex: /[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}/g,
    replacer: (m: string) => redact(m),
  },

  // GitHub
  {
    label: "GitHubTokenDetector",
    regex: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}/g,
    replacer: (m: string) => redact(m),
  },

  // GitLab (common prefixes)
  {
    label: "GitLabTokenDetector",
    regex: /(glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_-]{20,50}(?!\w)/g,
    replacer: (m: string) => redact(m),
  },

  // IBM Cloud IAM (assignment-focused, from detect-secrets)
  {
    label: "IbmCloudIamDetector",
    regex:
      /(\b(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)?(?:_|-|)?(?:api)?(?:_|-|)?(?:key|pwd|password|pass|token)\b\s*[:=]\s*)([a-zA-Z0-9_-]{44})(?![a-zA-Z0-9_-])/gi,
    replacer: (_m: string, p1: string, secret: string) => `${p1}${redact(secret)}`,
  },

  // IBM COS HMAC secret key (from detect-secrets)
  {
    label: "IbmCosHmacDetector",
    regex:
      /(\b(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?|)[\w-]*secret[-_]?(?:access)?[-_]?key\b\s*[:=]\s*)([a-f0-9]{48})(?![a-f0-9])/gi,
    replacer: (_m: string, p1: string, secret: string) => `${p1}${redact(secret)}`,
  },

  // Mailchimp
  {
    label: "MailchimpDetector",
    regex: /[0-9a-z]{32}-us[0-9]{1,2}/g,
    replacer: (m: string) => redact(m),
  },

  // NPM (from detect-secrets)
  {
    label: "NpmDetector",
    regex: /(\/\/.+\/:_authToken=\s*)(npm_.+|[A-Fa-f0-9-]{36})/g,
    replacer: (_m: string, p1: string, secret: string) => `${p1}${redact(secret)}`,
  },

  // OpenAI (from detect-secrets + legacy sk-48)
  {
    label: "OpenAIDetector",
    regex: /sk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
    replacer: (m: string) => redact(m),
  },
  {
    label: "OpenAIDetector",
    regex: /\bsk-[A-Za-z0-9]{48}\b/g,
    replacer: (m: string) => redact(m),
  },

  // PyPI tokens (from detect-secrets)
  {
    label: "PypiTokenDetector",
    regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{70,}/g,
    replacer: (m: string) => redact(m),
  },
  {
    label: "PypiTokenDetector",
    regex: /pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9-_]{70,}/g,
    replacer: (m: string) => redact(m),
  },

  // SendGrid
  {
    label: "SendGridDetector",
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    replacer: (m: string) => redact(m),
  },

  // Slack
  {
    label: "SlackDetector",
    regex: /xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+/gi,
    replacer: (m: string) => redact(m),
  },
  {
    label: "SlackDetector",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/gi,
    replacer: (m: string) => redact(m),
  },

  // SoftLayer (from detect-secrets)
  {
    label: "SoftlayerDetector",
    regex:
      /(\b(?:softlayer|sl)(?:_|-|)(?:api)?(?:_|-|)?(?:key|pwd|password|pass|token)\b\s*[:=]\s*)([a-z0-9]{64})\b/gi,
    replacer: (_m: string, p1: string, secret: string) => `${p1}${redact(secret)}`,
  },
  {
    label: "SoftlayerDetector",
    regex: /(?:http|https):\/\/api\.softlayer\.com\/soap\/(?:v3|v3\.1)\/([a-z0-9]{64})/gi,
    replacer: (m: string) => redact(m),
  },

  // Square OAuth secret
  {
    label: "SquareOAuthDetector",
    regex: /sq0csp-[0-9A-Za-z\-_]{43}/g,
    replacer: (m: string) => redact(m),
  },

  // Stripe
  {
    label: "StripeDetector",
    regex: /(?:r|s)k_live_[0-9a-zA-Z]{24}/g,
    replacer: (m: string) => redact(m),
  },
  {
    label: "StripeDetector",
    regex: /(?:r|s)k_test_[0-9a-zA-Z]{24}/g,
    replacer: (m: string) => redact(m),
  },

  // Telegram bot token
  {
    label: "TelegramBotTokenDetector",
    regex: /\b\d{8,10}:[0-9A-Za-z_-]{35}\b/g,
    replacer: (m: string) => redact(m),
  },

  // Twilio (from detect-secrets)
  {
    label: "TwilioKeyDetector",
    regex: /\bAC[a-z0-9]{32}\b/gi,
    replacer: (m: string) => redact(m),
  },
  {
    label: "TwilioKeyDetector",
    regex: /\bSK[a-z0-9]{32}\b/gi,
    replacer: (m: string) => redact(m),
  },

  // Email (PII)
  {
    label: "MailDetector",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replacer: (m: string) => redact(m),
  },
];

const JWT_REGEX = /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g;

// KeywordDetector: keep this conservative.
const KEYWORD_VALUE_REGEXES: RegExp[] = [
  // key: "value" / key = 'value'
  /\b\w*(api_?key|auth_?key|service_?key|account_?key|db_?pass|database_?pass|key_?pass|password|passwd|pwd|secret|token|private_?key|client_?secret)\w*\b\s*[:=]\s*(['"`])([^'"`\r\n]{4,})\2/gi,
  // key: value (unquoted)
  /\b\w*(api_?key|auth_?key|service_?key|account_?key|db_?pass|database_?pass|key_?pass|password|passwd|pwd|secret|token|private_?key|client_?secret)\w*\b\s*[:=]\s*([^\s"'`,;]{8,})/gi,
  // password is value
  /\b\w*(password|passwd|pwd|secret|token|api_?key)\w*\b\s+is\s+([^\s"'`,;]{8,})/gi,
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

      // Use typeof to distinguish real capture groups from positional metadata.
      // Regex with 2 groups passes offset (number) as g3, not a string.
      if (typeof g3 === "string") {
        const secret = String(g3);
        return String(m).replace(secret, redact(secret));
      }

      // Unquoted / "is" regex
      const secret = String(g2);
      return String(m).replace(secret, redact(secret));
    });
  }

  // JWT validation pass (only mask if formally valid)
  text = text.replace(JWT_REGEX, (m) => {
    if (looksLikeAlreadyMasked(m)) return m;
    if (!isJwtFormallyValid(m)) return m;

    bump(report, "JwtTokenDetector");
    return redact(m);
  });

  // High entropy passes
  // 1) quoted strings (we keep this broad, but only mask if the token passes the
  // specific base64/hex entropy checks)
  text = text.replace(/(['"])([^'"\r\n]{20,})(\1)/g, (_m, q, body, q2) => {
    const token = String(body);
    if (looksLikeAlreadyMasked(token)) return `${q}${token}${q2}`;

    if (hexEntropyPasses(token)) {
      bump(report, "HexHighEntropyString");
      return `${q}${redact(token)}${q2}`;
    }
    if (base64EntropyPasses(token)) {
      bump(report, "Base64HighEntropyString");
      return `${q}${redact(token)}${q2}`;
    }

    return `${q}${token}${q2}`;
  });

  // 2) context-aware token entropy
  text = text.replace(/\S+/g, (token: string, offset: number, fullString: string) => {
    if (looksLikeAlreadyMasked(token)) return token;

    const before = fullString.substring(0, offset);
    if (!hasKeywordContext(before)) return token;

    const clean = token.replace(/^['"([<{]+|['")\]>}]+$/g, "");
    if (clean.length < MIN_LENGTH_FOR_ENTROPY) return token;

    if (hexEntropyPasses(clean)) {
      bump(report, "HexHighEntropyString");
      return token.replace(clean, redact(clean));
    }
    if (base64EntropyPasses(clean)) {
      bump(report, "Base64HighEntropyString");
      return token.replace(clean, redact(clean));
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

function mergeMaskReports(target: Record<string, number>, next: Record<string, number>): void {
  for (const key in next) {
    target[key] = (target[key] || 0) + (next[key] || 0);
  }
}

function isNonTextDataUrlFilePart(part: any): boolean {
  return (
    part &&
    typeof part === "object" &&
    part.type === "file" &&
    typeof part.url === "string" &&
    part.url.startsWith("data:") &&
    typeof part.mime === "string" &&
    part.mime !== "text/plain"
  );
}

function maskUnknownStrings(input: unknown): {
  value: unknown;
  report: MaskReport;
  changed: boolean;
  fields: number;
  fieldsChanged: number;
  bytesIn: number;
  bytesOut: number;
} {
  const report: MaskReport = { triggered: false, countsByLabel: {} };
  const seen = new WeakMap<object, unknown>();

  let changed = false;
  let fields = 0;
  let fieldsChanged = 0;
  let bytesIn = 0;
  let bytesOut = 0;

  const walk = (value: unknown): unknown => {
    if (typeof value === "string") {
      fields += 1;
      bytesIn += utf8ByteLength(value);

      const res = maskSecrets(value);
      bytesOut += utf8ByteLength(res.masked);
      mergeMaskReports(report.countsByLabel, res.report.countsByLabel);

      if (res.masked !== value) {
        changed = true;
        fieldsChanged += 1;
      }

      return res.masked;
    }

    if (!value || typeof value !== "object") return value;
    if (seen.has(value as object)) return seen.get(value as object);

    if (Array.isArray(value)) {
      const next: unknown[] = [];
      seen.set(value, next);
      for (const item of value) next.push(walk(item));
      return next;
    }

    const src = value as Record<string, unknown>;
    const next: Record<string, unknown> = {};
    seen.set(value as object, next);
    for (const key in src) {
      next[key] = walk(src[key]);
    }
    return next;
  };

  const maskedValue = walk(input);
  report.triggered = sumCounts(report.countsByLabel) > 0;

  return {
    value: maskedValue,
    report,
    changed,
    fields,
    fieldsChanged,
    bytesIn,
    bytesOut,
  };
}

// --- OpenCode plugin (single-file) ---

const OpenCodeSecretMasker: Plugin = async ({ client }) => {
  await client.app.log({
    body: {
      service: "opencode-redactor",
      level: "info",
      message: "secret masker plugin initialized",
    },
  });

  return {
    // Observe and intercept events for early masking and audit.
    event: async ({ event }) => {
      try {
        if (!event || typeof event !== "object") return;

        const eventType = typeof (event as any).type === "string" ? (event as any).type : "";

        // Intercept completed tool-part events so the output is masked before it
        // is stored in conversation history and rendered in the TUI/run output.
        // This catches edit/write tool outputs that bypass tool.execute.after
        // because output.output is null when that hook fires.
        if (eventType === "message.part.updated") {
          const part = (event as any).properties?.part;
          if (part?.type === "tool" && part?.state?.status === "completed") {
            const state = part.state;
            const t0 = nowMs();
            const aggregateCounts: Record<string, number> = {};
            let changed = false;

            if (typeof state.output === "string" && state.output.length > 0) {
              const res = maskSecrets(state.output);
              if (res.masked !== state.output) {
                state.output = res.masked;
                mergeMaskReports(aggregateCounts, res.report.countsByLabel);
                changed = true;
              }
            }

            if (state.metadata && typeof state.metadata === "object") {
              const metaMasked = maskUnknownStrings(state.metadata);
              if (metaMasked.changed) {
                Object.assign(state.metadata, metaMasked.value);
                mergeMaskReports(aggregateCounts, metaMasked.report.countsByLabel);
                changed = true;
              }
            }

            if (changed) {
              const t1 = nowMs();
              const report: MaskReport = { triggered: true, countsByLabel: aggregateCounts };
              await appendAuditLog(report, {
                hook: "message.part.updated",
                durationMs: Math.max(0, t1 - t0),
                bytesIn: 0,
                tool: typeof part.tool === "string" ? part.tool : undefined,
              });
            }
          }
          return;
        }

        // Intercept session-diff events to mask file content shown in the diff viewer.
        if (eventType === "session.diff") {
          const diffs = (event as any).properties?.diff;
          if (Array.isArray(diffs)) {
            for (const fileDiff of diffs) {
              if (typeof fileDiff.before === "string") {
                const { masked } = maskSecrets(fileDiff.before);
                if (masked !== fileDiff.before) fileDiff.before = masked;
              }
              if (typeof fileDiff.after === "string") {
                const { masked } = maskSecrets(fileDiff.after);
                if (masked !== fileDiff.after) fileDiff.after = masked;
              }
            }
          }
          return;
        }

        if (eventType !== "tui.prompt.append" && eventType !== "tui.command.execute") {
          return;
        }

        const t0 = nowMs();
        const scanned = maskUnknownStrings(event);
        const t1 = nowMs();

        if (!scanned.report.triggered) return;

        await appendAuditLog(scanned.report, {
          hook: eventType,
          durationMs: Math.max(0, t1 - t0),
          bytesIn: scanned.bytesIn,
          bytesOut: scanned.bytesOut,
          fields: scanned.fields,
          fieldsChanged: scanned.fieldsChanged,
          sessionID:
            typeof (event as any)?.properties?.sessionID === "string"
              ? (event as any).properties.sessionID
              : undefined,
        });

        await client.app.log({
          body: {
            service: "opencode-redactor",
            level: "warn",
            message: "secret-like content detected in tui event",
            extra: {
              eventType,
              countsByLabel: scanned.report.countsByLabel,
            },
          },
        });
      } catch {
        // Best-effort; never break event processing.
      }
    },

    // Last-line defense: mutate full outbound chat message list immediately
    // before provider request construction.
    "experimental.chat.messages.transform": async (_input, output) => {
      try {
        const messages = (output as any)?.messages;
        if (!Array.isArray(messages) || messages.length === 0) return;

        const t0 = nowMs();
        // IMPORTANT:
        // `SessionPrompt` calls this hook with `{ messages: sessionMessages }` but
        // then continues using the `sessionMessages` variable (it does not use the
        // return value of Plugin.trigger).
        // Therefore we MUST mutate the existing message/parts arrays in-place.
        let changed = false;
        let parts = 0;
        let partsChanged = 0;
        let bytesIn = 0;
        let bytesOut = 0;
        const aggregateCounts: Record<string, number> = {};
        let sessionID: string | undefined;
        let messageID: string | undefined;

        for (const msg of messages) {
          const msgParts = (msg as any)?.parts;
          if (!Array.isArray(msgParts) || msgParts.length === 0) continue;

          for (let i = 0; i < msgParts.length; i++) {
            const part = msgParts[i];
            if (!sessionID && typeof part?.sessionID === "string") sessionID = part.sessionID;
            if (!messageID && typeof part?.messageID === "string") messageID = part.messageID;

            // Avoid corrupting binary/base64 file payloads.
            if (isNonTextDataUrlFilePart(part)) continue;

            const masked = maskUnknownStrings(part);
            if (masked.bytesIn > 0) parts += 1;
            bytesIn += masked.bytesIn;
            bytesOut += masked.bytesOut;
            mergeMaskReports(aggregateCounts, masked.report.countsByLabel);

            if (!masked.changed) continue;
            msgParts[i] = masked.value as any;
            changed = true;
            partsChanged += 1;
          }
        }

        if (!changed) return;

        const t1 = nowMs();

        const report: MaskReport = {
          triggered: sumCounts(aggregateCounts) > 0,
          countsByLabel: aggregateCounts,
        };

        if (!report.triggered) return;

        await appendAuditLog(report, {
          hook: "experimental.chat.messages.transform",
          durationMs: Math.max(0, t1 - t0),
          bytesIn,
          bytesOut,
          parts,
          partsChanged,
          sessionID,
          messageID,
        });
      } catch {
        // Best-effort; never break provider request.
      }
    },

    // Mask secrets in user-pasted text before it is persisted/sent.
    "chat.message": async (_input, output) => {
      try {
        // If true, redact what gets persisted to the session.
        // Default is false so users can paste secrets locally while the provider-bound
        // request is redacted in experimental.chat.messages.transform.
        const maskLocal = envTruthy("OPENCODE_REDACTOR_MASK_LOCAL", false);

        const t0 = nowMs();
        const parts = output.parts as any[];
        if (!Array.isArray(parts) || parts.length === 0) return;

        let partsChanged = 0;
        let bytesIn = 0;
        let bytesOut = 0;
        const aggregateCounts: Record<string, number> = {};

        // For user flow: fail-open. Always audit; only mutate stored parts when requested.
        for (let i = 0; i < parts.length; i++) {
          const part = parts[i];
          if (isNonTextDataUrlFilePart(part)) continue;

          const masked = maskUnknownStrings(part);
          bytesIn += masked.bytesIn;
          bytesOut += masked.bytesOut;
          mergeMaskReports(aggregateCounts, masked.report.countsByLabel);

          if (!masked.changed) continue;
          partsChanged += 1;
          if (maskLocal) {
            parts[i] = masked.value as any;
          }
        }

        const t1 = nowMs();

        const report: MaskReport = {
          triggered: sumCounts(aggregateCounts) > 0,
          countsByLabel: aggregateCounts,
        };

        if (!report.triggered) return;
        await appendAuditLog(report, {
          hook: "chat.message",
          durationMs: Math.max(0, t1 - t0),
          bytesIn,
          bytesOut,
          parts: parts.length,
          partsChanged,
          sessionID:
            typeof (_input as any)?.sessionID === "string" ? (_input as any).sessionID : undefined,
          messageID:
            typeof (_input as any)?.messageID === "string" ? (_input as any).messageID : undefined,
        });
      } catch {
        // Best-effort; never break chat.
      }
    },

    // Mask secrets introduced by tool outputs (read/grep/bash/etc).
    "tool.execute.after": async (input, output) => {
      try {
        const toolName = typeof (input as any)?.tool === "string" ? (input as any).tool : undefined;
        const t0 = nowMs();
        const aggregateCounts: Record<string, number> = {};
        let anyChanged = false;

        // --- mask output.output ---
        const raw = (output as any)?.output;
        if (raw != null) {
          if (typeof raw === "string") {
            if (raw.length > 0) {
              const res = maskSecrets(raw);
              if (res.masked !== raw) {
                (output as any).output = res.masked;
                mergeMaskReports(aggregateCounts, res.report.countsByLabel);
                anyChanged = true;
              }
            }
          } else if (typeof raw === "object") {
            const transformed = maskUnknownStrings(raw);
            if (transformed.changed) {
              (output as any).output = transformed.value;
              mergeMaskReports(aggregateCounts, transformed.report.countsByLabel);
              anyChanged = true;
            }
          }
        }

        // --- also mask output.metadata (edit tool stores diff here in some versions) ---
        const meta = (output as any)?.metadata;
        if (meta != null && typeof meta === "object") {
          const metaMasked = maskUnknownStrings(meta);
          if (metaMasked.changed) {
            (output as any).metadata = metaMasked.value;
            mergeMaskReports(aggregateCounts, metaMasked.report.countsByLabel);
            anyChanged = true;
          }
        }

        if (!anyChanged) return;

        const t1 = nowMs();
        await appendAuditLog(
          { triggered: true, countsByLabel: aggregateCounts },
          {
            hook: "tool.execute.after",
            durationMs: Math.max(0, t1 - t0),
            bytesIn: 0,
            tool: toolName,
          },
        );
      } catch {
        // Best-effort; never break tool execution.
      }
    },

    // Restore redacted tokens to original values before write/edit tools execute.
    "tool.execute.before": async (input, output) => {
      try {
        const tool = typeof (input as any)?.tool === "string" ? (input as any).tool : "";
        const args = (output as any)?.args;
        if (!args || typeof args !== "object") return;
        if (!isWriteTool(tool)) return;

        const t0 = nowMs();
        const argsJson = JSON.stringify(args);
        const tokenMatches = argsJson.match(REDACTED_TOKEN_RE);
        const tokensFound = tokenMatches ? tokenMatches.length : 0;

        // Always log for write tools — even when no tokens found — so the audit
        // trail shows the hook ran (tokensFound:0 = narrow edit, no masked region).
        if (tokensFound === 0) {
          const t1 = nowMs();
          await appendAuditLog(
            { triggered: false, countsByLabel: {} },
            {
              hook: "tool.execute.before",
              durationMs: Math.max(0, t1 - t0),
              bytesIn: utf8ByteLength(argsJson),
              tool,
              tokensFound: 0,
            },
          );
          return;
        }

        const unmasked = unmaskArgs(args);

        if (containsUnresolvedTokens(unmasked)) {
          throw new Error(
            "opencode-redactor: blocked write containing unresolvable redaction tokens",
          );
        }

        (output as any).args = unmasked;

        const unmaskedJson = JSON.stringify(unmasked);
        const t1 = nowMs();
        await appendAuditLog(
          { triggered: true, countsByLabel: { unmask: tokensFound } },
          {
            hook: "tool.execute.before",
            durationMs: Math.max(0, t1 - t0),
            bytesIn: utf8ByteLength(argsJson),
            bytesOut: utf8ByteLength(unmaskedJson),
            tool,
            tokensFound,
            tokensRestored: tokensFound,
          },
        );
      } catch (err) {
        // Re-throw our own safety errors; swallow everything else.
        if (err instanceof Error && err.message.includes("opencode-redactor")) throw err;
      }
    },

    // Mask assistant completion text before it is rendered/persisted.
    "experimental.text.complete": async (_input, output) => {
      try {
        const raw = (output as any)?.text;
        if (typeof raw !== "string" || raw.length === 0) return;

        const t0 = nowMs();
        const bytesIn = utf8ByteLength(raw);

        const res = maskSecrets(raw);
        if (res.masked === raw) return;

        (output as any).text = res.masked;

        const t1 = nowMs();
        await appendAuditLog(res.report, {
          hook: "experimental.text.complete",
          durationMs: Math.max(0, t1 - t0),
          bytesIn,
          bytesOut: utf8ByteLength(res.masked),
        });
      } catch {
        // Best-effort; never break completion flow.
      }
    },
  };
};

// OpenCode's plugin loader may attempt to call every exported function.
// Export a single default plugin function and attach internals for tests.
(OpenCodeSecretMasker as any).maskSecrets = maskSecrets;
(OpenCodeSecretMasker as any).appendAuditLog = appendAuditLog;
(OpenCodeSecretMasker as any).tokenRegistry = tokenRegistry;
(OpenCodeSecretMasker as any).resetTokenRegistry = resetTokenRegistry;
(OpenCodeSecretMasker as any).unmaskString = unmaskString;
(OpenCodeSecretMasker as any).unmaskArgs = unmaskArgs;
(OpenCodeSecretMasker as any).containsUnresolvedTokens = containsUnresolvedTokens;
(OpenCodeSecretMasker as any).isWriteTool = isWriteTool;

export default OpenCodeSecretMasker;
