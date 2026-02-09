import secretMasker from "./secret-masker";

import { describe, expect, test } from "bun:test";

type TestCase = {
  name: string;
  input: string;
  expected: string;
};

const testCases: TestCase[] = [
  {
    name: "ArtifactoryDetector",
    input: "Run with AKC1234567890abcdef1234567890.",
    expected: "<SECRET: ArtifactoryDetector>",
  },
  {
    name: "AWSKeyDetector (Access Key ID)",
    input: "My AWS key is AKIAIOSFODNN7EXAMPLE.",
    expected: "<SECRET: AWSKeyDetector>",
  },
  {
    name: "AWSKeyDetector (Secret Access Key)",
    input: "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    expected: "<SECRET: AWSKeyDetector>",
  },
  {
    name: "AzureStorageKeyDetector",
    input:
      "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHijklmnopqrstuvwxyz0123456789+/=abcdefghijklmnopqrstuvwxyzABCDEFGH==;EndpointSuffix=core.windows.net",
    expected: "AccountKey=<SECRET: AzureStorageKeyDetector>",
  },
  {
    name: "BasicAuthDetector (URL)",
    input: "https://user:supersecret@example.com/path",
    expected: "https://user:<SECRET: BasicAuthDetector>@example.com/path",
  },
  {
    name: "BasicAuthDetector (Header)",
    input: "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM=",
    expected: "Authorization: Basic <SECRET: BasicAuthDetector>",
  },
  {
    name: "CloudantDetector (URL)",
    input:
      "https://myacct:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@myacct.cloudant.com",
    expected: "<SECRET: CloudantDetector>",
  },
  {
    name: "DiscordBotTokenDetector",
    input: "Bot token: MTAwMDAwMDAwMDAwMDAwMDAwMA.ABCdef.aBCdEFgHiJKlMNopQRsTUVwXyZ1",
    expected: "<SECRET: DiscordBotTokenDetector>",
  },
  {
    name: "GitHubTokenDetector",
    input: "ghp_123456789012345678901234567890123456",
    expected: "<SECRET: GitHubTokenDetector>",
  },
  {
    name: "GitLabTokenDetector",
    input: "glpat-abcdef1234567890ABCD",
    expected: "<SECRET: GitLabTokenDetector>",
  },
  {
    name: "IbmCloudIamDetector",
    input: "ibm_cloud_iam_api_key: " + "a".repeat(44),
    expected: "<SECRET: IbmCloudIamDetector>",
  },
  {
    name: "IbmCosHmacDetector",
    input: "ibm_cos_hmac_secret_access_key = 0123456789abcdef0123456789abcdef0123456789abcdef",
    expected: "<SECRET: IbmCosHmacDetector>",
  },
  {
    name: "JwtTokenDetector (Formal validation)",
    input:
      "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    expected: "<SECRET: JwtTokenDetector>",
  },
  {
    name: "KeywordDetector",
    input: "password = \"dontlogme\"",
    expected: "<SECRET: KeywordDetector>",
  },
  {
    name: "MailchimpDetector",
    input: "0123456789abcdef0123456789abcdef-us1",
    expected: "<SECRET: MailchimpDetector>",
  },
  {
    name: "NpmDetector",
    input: "//registry.npmjs.org/:_authToken=npm_0123456789abcdef0123456789abcdef0123",
    expected: "//registry.npmjs.org/:_authToken=<SECRET: NpmDetector>",
  },
  {
    name: "OpenAIDetector",
    input: "sk-aaaaaaaaaaaaaaaaaaaaT3BlbkFJbbbbbbbbbbbbbbbbbbbb",
    expected: "<SECRET: OpenAIDetector>",
  },
  {
    name: "PypiTokenDetector",
    input: "pypi-AgEIcHlwaS5vcmc" + "A".repeat(80),
    expected: "<SECRET: PypiTokenDetector>",
  },
  {
    name: "SendGridDetector",
    input: "SG.1234567890123456789012.1234567890123456789012345678901234567890123",
    expected: "<SECRET: SendGridDetector>",
  },
  {
    name: "SlackDetector (Webhook)",
    input: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    expected: "<SECRET: SlackDetector>",
  },
  {
    name: "SoftlayerDetector",
    input: "softlayer_api_key = a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    expected: "<SECRET: SoftlayerDetector>",
  },
  {
    name: "SquareOAuthDetector",
    input: "sq0csp-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghiJKL",
    expected: "<SECRET: SquareOAuthDetector>",
  },
  {
    name: "StripeDetector",
    input: "sk_live_1234567890abcdef12345678",
    expected: "<SECRET: StripeDetector>",
  },
  {
    name: "TelegramBotTokenDetector",
    input: "123456789:" + "A".repeat(35),
    expected: "<SECRET: TelegramBotTokenDetector>",
  },
  {
    name: "TwilioKeyDetector",
    input: "SK1234567890abcdef1234567890abcdef",
    expected: "<SECRET: TwilioKeyDetector>",
  },
  {
    name: "Base64HighEntropyString (quoted)",
    input:
      "const x = \"dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=\";",
    expected: "<SECRET: Base64HighEntropyString>",
  },
  {
    name: "HexHighEntropyString (quoted)",
    input:
      "const x = \"7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c\";",
    expected: "<SECRET: HexHighEntropyString>",
  },
  {
    name: "Entropy WITHOUT Context (unquoted)",
    input:
      "This is a random hash 7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c inside a sentence.",
    expected:
      "This is a random hash 7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c inside a sentence.",
  },
];

describe("secret-masker", () => {
  for (const tc of testCases) {
    test(tc.name, async () => {
      const result = (secretMasker as any).maskSecrets(tc.input).masked;

      if (tc.expected === tc.input) {
        expect(result).toBe(tc.expected);
      } else {
        expect(result).toContain(tc.expected);
      }
    });
  }
});
