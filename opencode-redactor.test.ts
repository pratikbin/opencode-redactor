import redactor from "./opencode-redactor";

import { beforeEach, describe, expect, test } from "bun:test";

const maskSecrets = (redactor as any).maskSecrets as (text: string) => {
  masked: string;
  report: any;
};
const resetTokenRegistry = (redactor as any).resetTokenRegistry as () => void;
const unmaskString = (redactor as any).unmaskString as (text: string) => string;
const unmaskArgs = (redactor as any).unmaskArgs as (args: any) => any;
const containsUnresolvedTokens = (redactor as any).containsUnresolvedTokens as (
  args: any,
) => boolean;
const isWriteTool = (redactor as any).isWriteTool as (name: string) => boolean;
const tokenRegistry = (redactor as any).tokenRegistry as {
  valueToToken: Map<string, string>;
  tokenToValue: Map<string, string>;
};

const REDACTED_RE = /<REDACTED:[a-f0-9]{14}>/;

// Build test tokens at runtime so they don't appear as literal secrets in git history.
const s = (...parts: string[]) => parts.join("");

type TestCase = {
  name: string;
  input: string;
  secretPortion?: string; // the actual secret value that should be masked
  contextPrefix?: string; // preserved prefix (e.g. "AccountKey=")
  contextSuffix?: string; // preserved suffix (e.g. "@example.com/path")
  shouldMask: boolean;
};

const testCases: TestCase[] = [
  {
    name: "ArtifactoryDetector",
    input: "Run with AKC1234567890abcdef1234567890.",
    shouldMask: true,
  },
  {
    name: "AWSKeyDetector (Access Key ID)",
    input: "My AWS key is " + s("AKIA", "IOSF", "ODNN", "7EXA", "MPLE") + ".",
    secretPortion: s("AKIA", "IOSF", "ODNN", "7EXA", "MPLE"),
    shouldMask: true,
  },
  {
    name: "AWSKeyDetector (Secret Access Key)",
    input: "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    secretPortion: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    shouldMask: true,
  },
  {
    name: "AzureStorageKeyDetector",
    input:
      "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHijklmnopqrstuvwxyz0123456789+/=abcdefghijklmnopqrstuvwxyzABCDEFGH==;EndpointSuffix=core.windows.net",
    contextPrefix: "AccountKey=",
    shouldMask: true,
  },
  {
    name: "BasicAuthDetector (URL)",
    input: "https://user:supersecret@example.com/path",
    secretPortion: "supersecret",
    contextPrefix: "user:",
    contextSuffix: "@example.com/path",
    shouldMask: true,
  },
  {
    name: "BasicAuthDetector (Header)",
    input: "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM=",
    contextPrefix: "Basic ",
    shouldMask: true,
  },
  {
    name: "CloudantDetector (URL)",
    input:
      "https://myacct:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@myacct.cloudant.com",
    shouldMask: true,
  },
  {
    name: "DiscordBotTokenDetector",
    input:
      "Bot token: " +
      s(
        "MTAwMDAw",
        "MDAwMDAw",
        "MDAwMDAw",
        "MDAwMA",
        ".",
        "ABC",
        "def",
        ".",
        "aBCdEFg",
        "HiJKlMN",
        "opQRsTU",
        "VwXyZ1",
      ),
    shouldMask: true,
  },
  {
    name: "GitHubTokenDetector",
    input: s("ghp_", "123456789012", "345678901234", "567890123456"),
    shouldMask: true,
  },
  {
    name: "GitLabTokenDetector",
    input: s("glpat-", "abcdef1234", "567890ABCD"),
    shouldMask: true,
  },
  {
    name: "IbmCloudIamDetector",
    input: "ibm_cloud_iam_api_key: " + "a".repeat(44),
    contextPrefix: "ibm_cloud_iam_api_key: ",
    shouldMask: true,
  },
  {
    name: "IbmCosHmacDetector",
    input: "ibm_cos_hmac_secret_access_key = 0123456789abcdef0123456789abcdef0123456789abcdef",
    contextPrefix: "ibm_cos_hmac_secret_access_key = ",
    shouldMask: true,
  },
  {
    name: "JwtTokenDetector (Formal validation)",
    input:
      "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    shouldMask: true,
  },
  {
    name: "KeywordDetector",
    input: 'password = "dontlogme"',
    secretPortion: "dontlogme",
    shouldMask: true,
  },
  {
    name: "MailchimpDetector",
    input: s("01234567", "89abcdef", "01234567", "89abcdef", "-us", "1"),
    shouldMask: true,
  },
  {
    name: "NpmDetector",
    input: "//registry.npmjs.org/:_authToken=npm_0123456789abcdef0123456789abcdef0123",
    contextPrefix: "//registry.npmjs.org/:_authToken=",
    shouldMask: true,
  },
  {
    name: "OpenAIDetector",
    input: s("sk-", "aaaaaaaaaa", "aaaaaaaaaa", "T3BlbkFJ", "bbbbbbbbbb", "bbbbbbbbbb"),
    shouldMask: true,
  },
  {
    name: "PypiTokenDetector",
    input: "pypi-AgEIcHlwaS5vcmc" + "A".repeat(80),
    shouldMask: true,
  },
  {
    name: "SendGridDetector",
    input: "SG.1234567890123456789012.1234567890123456789012345678901234567890123",
    shouldMask: true,
  },
  {
    name: "SlackDetector (Webhook)",
    input: s(
      "https://hooks.slack.com/services/",
      "T00000000",
      "/",
      "B00000000",
      "/",
      "XXXXXXXX",
      "XXXXXXXX",
      "XXXXXXXX",
    ),
    shouldMask: true,
  },
  {
    name: "SoftlayerDetector",
    input: "softlayer_api_key = a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    contextPrefix: "softlayer_api_key = ",
    shouldMask: true,
  },
  {
    name: "SquareOAuthDetector",
    input: "sq0csp-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghiJKL",
    shouldMask: true,
  },
  {
    name: "StripeDetector",
    input: "sk_live_1234567890abcdef12345678",
    shouldMask: true,
  },
  {
    name: "TelegramBotTokenDetector",
    input: "123456789:" + "A".repeat(35),
    shouldMask: true,
  },
  {
    name: "TwilioKeyDetector",
    input: "SK1234567890abcdef1234567890abcdef",
    shouldMask: true,
  },
  {
    name: "Base64HighEntropyString (quoted)",
    input: 'const x = "dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=";',
    shouldMask: true,
  },
  {
    name: "HexHighEntropyString (quoted)",
    input: 'const x = "7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c";',
    shouldMask: true,
  },
  {
    name: "Entropy WITHOUT Context (unquoted)",
    input: "This is a random hash 7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c inside a sentence.",
    shouldMask: false,
  },
];

describe("opencode-redactor", () => {
  beforeEach(() => {
    resetTokenRegistry();
  });

  describe("detector masking", () => {
    for (const tc of testCases) {
      test(tc.name, () => {
        const { masked } = maskSecrets(tc.input);

        if (!tc.shouldMask) {
          expect(masked).toBe(tc.input);
          return;
        }

        // Output must contain a reversible REDACTED token
        expect(masked).toMatch(REDACTED_RE);

        // Secret portion should not appear in output
        if (tc.secretPortion) {
          expect(masked).not.toContain(tc.secretPortion);
        }

        // Context prefix should be preserved
        if (tc.contextPrefix) {
          expect(masked).toContain(tc.contextPrefix);
        }

        // Context suffix should be preserved
        if (tc.contextSuffix) {
          expect(masked).toContain(tc.contextSuffix);
        }
      });
    }
  });

  describe("round-trip (mask → unmask)", () => {
    for (const tc of testCases) {
      if (!tc.shouldMask) continue;

      test(`${tc.name} round-trip`, () => {
        const { masked } = maskSecrets(tc.input);
        const restored = unmaskString(masked);
        expect(restored).toBe(tc.input);
      });
    }
  });
});

describe("token registry", () => {
  beforeEach(() => {
    resetTokenRegistry();
  });

  test("same secret produces same token (idempotent)", () => {
    const { masked: first } = maskSecrets("sk_live_1234567890abcdef12345678");
    const { masked: second } = maskSecrets("sk_live_1234567890abcdef12345678");
    expect(first).toBe(second);
  });

  test("different secrets produce different tokens", () => {
    const { masked: first } = maskSecrets("sk_live_1234567890abcdef12345678");
    const { masked: second } = maskSecrets("sk_live_aaaaaaaaaaaaaaaaaaaaaaaa");
    expect(first).not.toBe(second);
  });

  test("token format matches <REDACTED:14hexchars>", () => {
    const { masked } = maskSecrets("sk_live_1234567890abcdef12345678");
    expect(masked).toMatch(/^<REDACTED:[a-f0-9]{14}>$/);
  });

  test("registry tracks bidirectional mapping", () => {
    const secret = "sk_live_1234567890abcdef12345678";
    const { masked } = maskSecrets(secret);
    expect(tokenRegistry.valueToToken.has(secret)).toBe(true);
    expect(tokenRegistry.tokenToValue.has(masked)).toBe(true);
    expect(tokenRegistry.tokenToValue.get(masked)).toBe(secret);
  });

  test("registry grows for each unique secret", () => {
    maskSecrets("sk_live_aaaaaaaaaaaaaaaaaaaaaaaA");
    maskSecrets("sk_live_bbbbbbbbbbbbbbbbbbbbbbbB");
    expect(tokenRegistry.valueToToken.size).toBe(2);
  });

  test("reset clears all state", () => {
    maskSecrets("sk_live_1234567890abcdef12345678");
    expect(tokenRegistry.valueToToken.size).toBeGreaterThan(0);
    resetTokenRegistry();
    expect(tokenRegistry.valueToToken.size).toBe(0);
    expect(tokenRegistry.tokenToValue.size).toBe(0);
  });
});

describe("unmask utilities", () => {
  beforeEach(() => {
    resetTokenRegistry();
  });

  test("unmaskString restores tokens", () => {
    const secret = s("ghp_", "123456789012", "345678901234", "567890123456");
    const { masked } = maskSecrets(secret);
    expect(unmaskString(masked)).toBe(secret);
  });

  test("unmaskString leaves unknown tokens intact", () => {
    const fake = "<REDACTED:deadbeef1234ab>";
    expect(unmaskString(fake)).toBe(fake);
  });

  test("unmaskArgs walks objects recursively", () => {
    const secret = "sk_live_1234567890abcdef12345678";
    const { masked } = maskSecrets(secret);

    const args = { content: `file has ${masked} inside`, nested: { deep: masked } };
    const restored = unmaskArgs(args);
    expect(restored.content).toBe(`file has ${secret} inside`);
    expect(restored.nested.deep).toBe(secret);
  });

  test("unmaskArgs walks arrays", () => {
    const secret = "sk_live_1234567890abcdef12345678";
    const { masked } = maskSecrets(secret);

    const restored = unmaskArgs([masked, "plain", [masked]]);
    expect(restored[0]).toBe(secret);
    expect(restored[1]).toBe("plain");
    expect(restored[2][0]).toBe(secret);
  });

  test("containsUnresolvedTokens returns false when all resolved", () => {
    const secret = "sk_live_1234567890abcdef12345678";
    const { masked } = maskSecrets(secret);
    expect(containsUnresolvedTokens({ content: masked })).toBe(false);
  });

  test("containsUnresolvedTokens returns true for unknown tokens", () => {
    expect(containsUnresolvedTokens({ content: "<REDACTED:deadbeef1234ab>" })).toBe(true);
  });
});

describe("isWriteTool", () => {
  test("recognizes write tools", () => {
    expect(isWriteTool("file_write")).toBe(true);
    expect(isWriteTool("file_edit")).toBe(true);
    expect(isWriteTool("patch")).toBe(true);
    expect(isWriteTool("create_file")).toBe(true);
    expect(isWriteTool("save")).toBe(true);
    expect(isWriteTool("update_file")).toBe(true);
  });

  test("rejects non-write tools", () => {
    expect(isWriteTool("read")).toBe(false);
    expect(isWriteTool("grep")).toBe(false);
    expect(isWriteTool("bash")).toBe(false);
    expect(isWriteTool("list_files")).toBe(false);
    expect(isWriteTool("")).toBe(false);
  });
});

describe("looksLikeAlreadyMasked", () => {
  beforeEach(() => {
    resetTokenRegistry();
  });

  test("does not double-mask REDACTED tokens", () => {
    const secret = "sk_live_1234567890abcdef12345678";
    const { masked } = maskSecrets(secret);
    // Masking the already-masked output should be a no-op
    const { masked: doubleMasked } = maskSecrets(masked);
    expect(doubleMasked).toBe(masked);
  });
});

describe("tool.execute.before hook (unmask on write)", () => {
  let hooks: any;

  beforeEach(async () => {
    resetTokenRegistry();
    const mockClient = { app: { log: async () => {} } };
    hooks = await (redactor as any)({ client: mockClient });
  });

  test("restores tokens in write tool args", async () => {
    const secret = "sk_live_1234567890abcdef12345678";
    const { masked } = maskSecrets(secret);

    const output = { args: { file_path: "/tmp/test.txt", content: `key=${masked}` } };
    await hooks["tool.execute.before"]({ tool: "file_write" }, output);
    expect(output.args.content).toBe(`key=${secret}`);
  });

  test("skips non-write tools", async () => {
    const secret = "sk_live_1234567890abcdef12345678";
    const { masked } = maskSecrets(secret);

    const output = { args: { query: masked } };
    await hooks["tool.execute.before"]({ tool: "grep" }, output);
    // Args unchanged because grep is not a write tool
    expect(output.args.query).toBe(masked);
  });

  test("blocks writes with unresolvable tokens", async () => {
    const output = { args: { content: "<REDACTED:deadbeef1234ab>" } };
    await expect(hooks["tool.execute.before"]({ tool: "file_write" }, output)).rejects.toThrow(
      "opencode-redactor: blocked write containing unresolvable redaction tokens",
    );
  });

  test("passes through when no tokens in registry", async () => {
    const output = { args: { content: "plain text" } };
    await hooks["tool.execute.before"]({ tool: "file_write" }, output);
    expect(output.args.content).toBe("plain text");
  });

  test("handles nested args in edit tool", async () => {
    const secret = s("ghp_", "123456789012", "345678901234", "567890123456");
    const { masked } = maskSecrets(secret);

    const output = {
      args: {
        file_path: "/tmp/test.ts",
        old_string: `const token = "${masked}";`,
        new_string: `const token = "${masked}";`,
      },
    };
    await hooks["tool.execute.before"]({ tool: "file_edit" }, output);
    expect(output.args.old_string).toBe(`const token = "${secret}";`);
    expect(output.args.new_string).toBe(`const token = "${secret}";`);
  });
});

describe("full pipeline: mask in tool.execute.after → unmask in tool.execute.before", () => {
  let hooks: any;

  beforeEach(async () => {
    resetTokenRegistry();
    const mockClient = { app: { log: async () => {} } };
    hooks = await (redactor as any)({ client: mockClient });
  });

  test("read → write round-trip preserves file content", async () => {
    const fileContent = [
      "DB_HOST=localhost",
      'DB_PASSWORD="SuperSecret123!@#$%^&*()"',
      "API_KEY=sk_live_1234567890abcdef12345678",
      "NORMAL_VAR=hello",
    ].join("\n");

    // Simulate tool.execute.after (file read)
    const afterOutput = { output: fileContent };
    await hooks["tool.execute.after"]({ tool: "file_read" }, afterOutput);
    const maskedContent = afterOutput.output;

    // Secrets should be masked
    expect(maskedContent).not.toContain("sk_live_1234567890abcdef12345678");
    expect(maskedContent).toContain("<REDACTED:");
    // Non-secret content preserved
    expect(maskedContent).toContain("DB_HOST=localhost");
    expect(maskedContent).toContain("NORMAL_VAR=hello");

    // Simulate tool.execute.before (file write-back of masked content)
    const beforeOutput = { args: { file_path: "/tmp/.env", content: maskedContent } };
    await hooks["tool.execute.before"]({ tool: "file_write" }, beforeOutput);

    // Original content restored
    expect(beforeOutput.args.content).toBe(fileContent);
  });
});
