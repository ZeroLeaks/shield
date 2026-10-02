import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { ToolPolicyError } from "../errors";
import {
  createToolPolicy,
  globMatch,
  guessToolLabels,
  type ToolPolicyDecision,
} from "../policy";
import { planPattern } from "../policy/pattern";
import { validateSchema } from "../policy/schema";
import { fakeGitHubToken } from "./fake-secrets";

const TOKEN = fakeGitHubToken();

const SEND_EMAIL_SCHEMA = {
  type: "object",
  properties: {
    to: { type: "string" },
    subject: { type: "string", maxLength: 100 },
    body: { type: "string" },
  },
  required: ["to", "body"],
  additionalProperties: false,
};

const SEND_EMAIL = {
  name: "send_email",
  description: "Send an email.",
  inputSchema: SEND_EMAIL_SCHEMA,
};

const READ_INBOX = {
  name: "read_inbox",
  description: "Read new email.",
  inputSchema: { type: "object", properties: {} },
};

const email = (to: string) => ({
  name: "send_email",
  arguments: { to, body: "Hi" },
});

/** A policy whose session has read the inbox. */
function afterInbox(options: Parameters<typeof createToolPolicy>[0] = {}) {
  const policy = createToolPolicy({
    ...options,
    rules: {
      read_inbox: { labels: ["untrusted", "private"] },
      send_email: { labels: ["sink"] },
      ...options.rules,
    },
  });
  policy.recordResult("read_inbox");
  return policy;
}

describe("createToolPolicy", () => {
  it("allows every call and counts it when nothing is configured", () => {
    const policy = createToolPolicy();

    const decision = policy.check({ name: "anything", arguments: "{}" });

    expect(decision).toEqual({
      allowed: true,
      reason: "allowed",
      message: "Allowed.",
      tool: "anything",
    });
    expect(policy.state().calls).toEqual({ anything: 1 });
  });

  it("rejects bad limits and flow values when it is created", () => {
    expect(() => createToolPolicy({ maxTotalCalls: -1 })).toThrow(RangeError);
    expect(() => createToolPolicy({ rules: { a: { maxCalls: 1.5 } } })).toThrow(
      RangeError
    );
    expect(() =>
      createToolPolicy({ flow: "sometimes" as unknown as false })
    ).toThrow(TypeError);
  });
});

describe("declared tools", () => {
  it("refuses a name that was not declared", () => {
    const policy = createToolPolicy({ tools: [SEND_EMAIL, READ_INBOX] });

    expect(policy.check({ name: "read_inbox" }).allowed).toBe(true);
    expect(policy.check({ name: "delete_repo" })).toMatchObject({
      allowed: false,
      reason: "undeclared_tool",
      tool: "delete_repo",
      message: 'Tool "delete_repo" is not a declared tool.',
    });
    expect(policy.state().calls).toEqual({ read_inbox: 1 });
  });

  it("refuses everything once an empty list is declared", () => {
    const policy = createToolPolicy({ tools: [] });
    expect(policy.check({ name: "read_inbox" }).reason).toBe("undeclared_tool");
  });

  it.each([
    ["MCP", { name: "t", inputSchema: SEND_EMAIL_SCHEMA }],
    [
      "OpenAI Chat Completions",
      {
        type: "function",
        function: { name: "t", parameters: SEND_EMAIL_SCHEMA },
      },
    ],
    [
      "OpenAI Responses",
      { type: "function", name: "t", parameters: SEND_EMAIL_SCHEMA },
    ],
    ["Anthropic", { name: "t", input_schema: SEND_EMAIL_SCHEMA }],
  ])("reads the schema of %s tool definitions", (_, tool) => {
    const policy = createToolPolicy({ tools: [tool] });

    expect(policy.check({ name: "t", arguments: { to: "a" } })).toMatchObject({
      reason: "invalid_arguments",
      violations: [{ path: "$.body", keyword: "required" }],
    });
  });

  it("takes an object of tools by name, with AI SDK and Zod schemas", () => {
    const policy = createToolPolicy({
      tools: {
        wrapped: {
          inputSchema: {
            jsonSchema: SEND_EMAIL_SCHEMA,
            validate: () => ({ success: true }),
          },
        },
        zod: { inputSchema: z.object({ count: z.number().int().min(1) }) },
      },
    });

    expect(
      policy.check({ name: "wrapped", arguments: { to: "a", body: "b" } })
        .allowed
    ).toBe(true);
    expect(
      policy.check({ name: "zod", arguments: { count: 0 } })
    ).toMatchObject({
      reason: "invalid_arguments",
      violations: [{ path: "$.count", keyword: "minimum" }],
    });
    expect(policy.check({ name: "other" }).reason).toBe("undeclared_tool");
  });

  it("keeps each source's tools, and replaces them when the source declares again", () => {
    const policy = createToolPolicy({ tools: [READ_INBOX] });
    policy.declareTools([SEND_EMAIL], "mail");
    policy.declareTools([{ name: "create_issue" }], "github");

    expect(policy.check({ name: "read_inbox" }).allowed).toBe(true);
    expect(policy.check(email("a")).allowed).toBe(true);
    expect(policy.check({ name: "create_issue" }).allowed).toBe(true);

    policy.declareTools([{ name: "list_issues" }], "github");

    expect(policy.check({ name: "create_issue" }).reason).toBe(
      "undeclared_tool"
    );
    expect(policy.check({ name: "list_issues" }).allowed).toBe(true);
  });

  it("checks a call with a source against that source's tools, once it declared any", () => {
    const policy = createToolPolicy({ tools: [READ_INBOX] });
    policy.declareTools([SEND_EMAIL], "mail");

    expect(policy.check({ ...email("a"), source: "mail" }).allowed).toBe(true);
    expect(policy.check({ name: "read_inbox", source: "mail" }).reason).toBe(
      "undeclared_tool"
    );
    expect(policy.check({ name: "read_inbox", source: "other" }).allowed).toBe(
      true
    );
    expect(policy.check({ name: "unknown", source: "other" }).reason).toBe(
      "undeclared_tool"
    );
  });

  it("checks arguments against every schema declared for a name", () => {
    const policy = createToolPolicy({ tools: [SEND_EMAIL] });
    policy.declareTools(
      [
        {
          name: "send_email",
          inputSchema: {
            type: "object",
            properties: { to: { type: "string", maxLength: 3 } },
          },
        },
      ],
      "other"
    );

    expect(policy.check(email("abc")).allowed).toBe(true);
    expect(policy.check(email("abcd")).reason).toBe("invalid_arguments");
  });

  it("allows any arguments for a tool without a schema", () => {
    const policy = createToolPolicy({ tools: [{ name: "free" }] });
    expect(policy.check({ name: "free", arguments: "not json" }).allowed).toBe(
      true
    );
  });
});

describe("argument validation", () => {
  const policy = () => createToolPolicy({ tools: [SEND_EMAIL] });

  it("reads arguments as an object or a JSON string, and an empty string as {}", () => {
    expect(policy().check(email("a")).allowed).toBe(true);
    expect(
      policy().check({ name: "send_email", arguments: '{"to":"a","body":"b"}' })
        .allowed
    ).toBe(true);
    expect(
      policy().check({ name: "send_email", arguments: "  " }).violations
    ).toEqual([
      { path: "$.to", keyword: "required", message: "is required" },
      { path: "$.body", keyword: "required", message: "is required" },
    ]);
  });

  it("refuses arguments that are not JSON", () => {
    expect(
      policy().check({ name: "send_email", arguments: "{to: a}" })
    ).toMatchObject({
      allowed: false,
      reason: "invalid_arguments",
      violations: [{ path: "$", keyword: "json" }],
    });
  });

  it("lists where the arguments are wrong, but never their values", () => {
    const decision = policy().check({
      name: "send_email",
      arguments: {
        to: 42,
        body: TOKEN,
        subject: `${TOKEN} `.repeat(10),
        [TOKEN]: TOKEN,
      },
    });

    expect(decision.reason).toBe("invalid_arguments");
    expect(decision.violations).toEqual([
      { path: "$.to", keyword: "type", message: "must be string" },
      {
        path: "$.subject",
        keyword: "maxLength",
        message: "must be at most 100 characters",
      },
      {
        path: "$.*",
        keyword: "additionalProperties",
        message: "is not allowed",
      },
    ]);
    expect(decision.message).toBe(
      'The arguments for tool "send_email" don\'t match its schema: $.to must be string; $.subject must be at most 100 characters; $.* is not allowed.'
    );
    expect(JSON.stringify(decision)).not.toContain(TOKEN);
    expect(JSON.stringify(new ToolPolicyError(decision))).not.toContain(TOKEN);
  });

  it("skips validation with validateArguments: false", () => {
    const decision = createToolPolicy({
      tools: [SEND_EMAIL],
      validateArguments: false,
    }).check({ name: "send_email", arguments: { to: 42 } });

    expect(decision.allowed).toBe(true);
  });
});

describe("allow and deny lists", () => {
  it("refuses names off the allow list, with globs", () => {
    const policy = createToolPolicy({ allow: ["github_get_*", "read_inbox"] });

    expect(policy.check({ name: "github_get_issue" }).allowed).toBe(true);
    expect(policy.check({ name: "read_inbox" }).allowed).toBe(true);
    expect(policy.check({ name: "github_delete_repo" })).toMatchObject({
      reason: "tool_not_allowed",
      message: 'Tool "github_delete_repo" is not on the allow list.',
    });
  });

  it("refuses names on the deny list before the allow list", () => {
    const policy = createToolPolicy({
      allow: ["github_*"],
      deny: ["*_delete_*", "github_admin"],
    });

    expect(policy.check({ name: "github_get_issue" }).allowed).toBe(true);
    expect(policy.check({ name: "github_delete_repo" }).reason).toBe(
      "denied_tool"
    );
    expect(policy.check({ name: "github_admin" }).reason).toBe("denied_tool");
  });

  it("matches globs without regex semantics", () => {
    expect(globMatch("github_*", "github_")).toBe(true);
    expect(globMatch("*", "")).toBe(true);
    expect(globMatch("a*b*c", "aXXbYYc")).toBe(true);
    expect(globMatch("a*b*c", "aXXbYY")).toBe(false);
    expect(globMatch("a.b", "aXb")).toBe(false);
    expect(globMatch("read_inbox", "read_inbox2")).toBe(false);
    expect(globMatch(`${"*a".repeat(20)}b`, "a".repeat(200))).toBe(false);
  });
});

describe("call limits", () => {
  it("refuses a tool's calls past the lowest maxCalls of its rules, counting only allowed calls", () => {
    const policy = createToolPolicy({
      deny: ["blocked"],
      rules: {
        "github_*": { maxCalls: 5 },
        github_create_issue: { maxCalls: 2 },
      },
    });

    policy.check({ name: "github_create_issue" });
    policy.check({ name: "github_create_issue" });
    const third = policy.check({ name: "github_create_issue" });

    expect(third).toMatchObject({
      allowed: false,
      reason: "call_limit",
      message:
        'Tool "github_create_issue" reached its limit of 2 calls in this session.',
    });
    expect(policy.check({ name: "github_get_issue" }).allowed).toBe(true);
    policy.check({ name: "blocked" });
    expect(policy.state().calls).toEqual({
      github_create_issue: 2,
      github_get_issue: 1,
    });
  });

  it("refuses calls past maxTotalCalls, and reset() starts over", () => {
    const policy = createToolPolicy({ maxTotalCalls: 2 });
    policy.check({ name: "a" });
    policy.check({ name: "b" });

    expect(policy.check({ name: "c" })).toMatchObject({
      reason: "call_limit",
      message: "The session reached its limit of 2 tool calls.",
    });
    policy.reset();
    expect(policy.check({ name: "c" }).allowed).toBe(true);
  });
});

describe("flow rule", () => {
  it("allows a sink until the session has seen untrusted content", () => {
    const policy = createToolPolicy({
      rules: {
        read_inbox: { labels: ["untrusted"] },
        send_email: { labels: ["sink"] },
      },
    });

    expect(policy.check(email("a@example.invalid")).allowed).toBe(true);
    policy.recordResult("read_inbox");
    const refused = policy.check(email("a@example.invalid"));

    expect(refused).toEqual({
      allowed: false,
      reason: "untrusted_to_sink",
      tool: "send_email",
      message:
        'Tool "send_email" can send data out, and this session has seen untrusted content from read_inbox.',
    });
    expect(policy.check({ name: "read_inbox" }).allowed).toBe(true);
  });

  it("counts a flagged result, or recordUntrusted(), as untrusted content", () => {
    const flagged = createToolPolicy({
      rules: { send_email: { labels: ["sink"] } },
    });
    flagged.recordResult("get_weather");
    expect(flagged.check(email("a")).allowed).toBe(true);
    flagged.recordResult("get_weather", { flagged: true });
    expect(flagged.check(email("a")).reason).toBe("untrusted_to_sink");

    const recorded = createToolPolicy({
      rules: { send_email: { labels: ["sink"] } },
    });
    recorded.recordUntrusted("retrieved document");
    expect(recorded.check(email("a")).message).toContain(
      "from retrieved document"
    );
  });

  it("with flow: trifecta, refuses a sink only once untrusted content and private data were both seen", () => {
    const policy = createToolPolicy({
      flow: "trifecta",
      rules: {
        fetch_url: { labels: ["untrusted"] },
        get_contacts: { labels: ["private"] },
        send_email: { labels: ["sink"] },
      },
    });

    policy.recordResult("fetch_url");
    expect(policy.check(email("a")).allowed).toBe(true);
    policy.recordResult("get_contacts");
    expect(policy.check(email("a")).message).toBe(
      'Tool "send_email" can send data out, and this session has seen untrusted content from fetch_url and private data from get_contacts.'
    );
  });

  it("never refuses with flow: false, but still records", () => {
    const policy = afterInbox({ flow: false });

    expect(policy.check(email("a")).allowed).toBe(true);
    expect(policy.state().untrustedFrom).toEqual(["read_inbox"]);
  });

  it("applies the labels of every matching rule", () => {
    const policy = createToolPolicy({
      rules: {
        "github_*": { labels: ["sink"] },
        "github_get_*": { labels: ["untrusted"] },
      },
    });

    policy.recordResult("github_get_issue");
    expect(policy.check({ name: "github_get_issue" }).reason).toBe(
      "untrusted_to_sink"
    );
  });

  it("guesses labels only with guessLabels, and a rule's labels replace the guess", () => {
    const guessing = createToolPolicy({ guessLabels: true });
    const not = createToolPolicy();
    const overridden = createToolPolicy({
      guessLabels: true,
      rules: { send_email: { labels: [] } },
    });
    for (const policy of [guessing, not, overridden]) {
      policy.recordResult("read_inbox");
    }

    expect(guessing.check(email("a")).reason).toBe("untrusted_to_sink");
    expect(not.check(email("a")).allowed).toBe(true);
    expect(overridden.check(email("a")).allowed).toBe(true);
  });

  it("lets approve() allow a refused sink call, and counts it", () => {
    const approve = vi.fn(
      (call: { arguments?: unknown }, _: ToolPolicyDecision) =>
        (call.arguments as { to: string }).to === "ops@example.invalid"
    );
    const policy = afterInbox({ approve });

    expect(policy.check(email("ops@example.invalid"))).toEqual({
      allowed: true,
      reason: "approved",
      message: "Allowed by approve().",
      tool: "send_email",
    });
    expect(policy.check(email("x@example.invalid")).reason).toBe(
      "untrusted_to_sink"
    );
    expect(approve).toHaveBeenCalledWith(
      {
        name: "send_email",
        arguments: { to: "ops@example.invalid", body: "Hi" },
      },
      expect.objectContaining({ reason: "untrusted_to_sink" })
    );
    expect(policy.state().calls).toEqual({ send_email: 1 });
  });

  it("does not ask approve() about other refusals", () => {
    const approve = vi.fn(() => true);
    const policy = afterInbox({ approve, deny: ["delete_*"] });

    expect(policy.check({ name: "delete_repo" }).reason).toBe("denied_tool");
    expect(approve).not.toHaveBeenCalled();
  });

  it("waits for an async approve() in checkAsync(), and check() refuses to", async () => {
    const policy = afterInbox({ approve: () => Promise.resolve(true) });

    expect(() => policy.check(email("a"))).toThrow(TypeError);
    await expect(policy.checkAsync(email("a"))).resolves.toMatchObject({
      allowed: true,
      reason: "approved",
    });
  });

  it("checks the limits again after approve() answers", async () => {
    const answers: Array<(value: boolean) => void> = [];
    const policy = afterInbox({
      approve: () =>
        new Promise<boolean>((resolve) => {
          answers.push(resolve);
        }),
      rules: { send_email: { labels: ["sink"], maxCalls: 1 } },
    });

    const first = policy.checkAsync(email("a"));
    const second = policy.checkAsync(email("b"));
    for (const answer of answers) {
      answer(true);
    }

    await expect(first).resolves.toMatchObject({ reason: "approved" });
    await expect(second).resolves.toMatchObject({ reason: "call_limit" });
    expect(policy.state().calls).toEqual({ send_email: 1 });
  });
});

describe("destinations", () => {
  const policy = (allow: string[], args = ["to", "cc"]) =>
    afterInbox({
      rules: {
        send_email: {
          labels: ["sink"],
          destinations: { arguments: args, allow },
        },
      },
    });
  const send = (to: unknown, extra: Record<string, unknown> = {}) => ({
    name: "send_email",
    arguments: { to, body: "Hi", ...extra },
  });

  it.each([
    ["an email address at the domain", ["acme.example"], "ops@acme.example"],
    ["a named address", ["acme.example"], "Ops Team <ops@acme.example>"],
    ["a list of addresses", ["acme.example"], "a@acme.example, b@acme.example"],
    ["an array", ["acme.example"], ["a@acme.example", "b@acme.example"]],
    ["an exact address", ["ops@acme.example"], "OPS@acme.example"],
    ["a subdomain with a suffix entry", [".acme.example"], "a@eu.acme.example"],
    ["a URL's host", ["api.acme.example"], "https://api.acme.example/hooks/1"],
    ["a bare value", ["#general"], "#general"],
  ])("allows a sink after untrusted content for %s", (_, allow, to) => {
    expect(policy(allow).check(send(to)).allowed).toBe(true);
  });

  it.each([
    ["another domain", "ops@evil.invalid"],
    ["one bad address in a list", "a@acme.example; b@evil.invalid"],
    ["a subdomain without a suffix entry", "a@eu.acme.example"],
    ["a look-alike domain", "a@acme.example.evil.invalid"],
    ["userinfo in a URL", "https://acme.example@evil.invalid/"],
    ["a query that ends in the domain", "evil.invalid?x=.acme.example"],
    ["an address with two @", "a@evil.invalid@acme.example"],
    ["a value that isn't a string", { address: "a@acme.example" }],
    ["no destination at all", undefined],
  ])("refuses %s", (_, to) => {
    expect(policy(["acme.example"]).check(send(to)).reason).toBe(
      "untrusted_to_sink"
    );
  });

  it("checks every destination argument, including dotted paths", () => {
    const nested = policy(["acme.example"], ["message.to", "message.cc"]);

    expect(
      nested.check({
        name: "send_email",
        arguments: { message: { to: "a@acme.example", cc: "b@evil.invalid" } },
      }).allowed
    ).toBe(false);
    expect(
      nested.check({
        name: "send_email",
        arguments: { message: { to: "a@acme.example" } },
      }).allowed
    ).toBe(true);
    expect(
      policy(["acme.example"]).check(
        send("a@acme.example", { cc: "x@evil.invalid" })
      ).allowed
    ).toBe(false);
  });
});

describe("state", () => {
  it("returns a copy that survives a JSON round trip, and restores from it", () => {
    const policy = afterInbox();
    policy.check({ name: "__proto__" });
    policy.check({ name: "read_inbox" });
    const saved = JSON.parse(JSON.stringify(policy.state()));
    saved.untrustedFrom.push("tampered");

    const restored = createToolPolicy({
      state: saved,
      rules: { send_email: { labels: ["sink"] } },
      maxTotalCalls: 3,
    });

    expect(policy.state().untrustedFrom).toEqual(["read_inbox"]);
    expect(Object.getPrototypeOf(policy.state().calls)).toBe(Object.prototype);
    expect(restored.state().calls).toEqual(saved.calls);
    expect(restored.check(email("a")).reason).toBe("untrusted_to_sink");
    expect(restored.check({ name: "x" }).allowed).toBe(true);
    expect(restored.check({ name: "y" }).reason).toBe("call_limit");
  });
});

describe("guessToolLabels", () => {
  it.each([
    ["read_inbox", ["untrusted", "private"]],
    ["fetch_url", ["untrusted"]],
    ["web_search", ["untrusted"]],
    ["brave_web_search", ["untrusted"]],
    ["http_get", ["untrusted"]],
    ["github_list_pull_requests", ["untrusted"]],
    ["getIssueComments", ["untrusted"]],
    ["read_file", ["private"]],
    ["get_contacts", ["private"]],
    ["send_email", ["sink"]],
    ["slack_post_message", ["sink"]],
    ["github_create_issue", ["sink"]],
    ["add_comment", ["sink"]],
    ["http_post", ["sink"]],
    ["call_webhook", ["sink"]],
    ["http_request", ["untrusted", "sink"]],
    ["get_weather", []],
    ["list_webhooks", []],
    ["create_calendar_event", []],
    ["write_file", []],
    ["calculate", []],
  ])("%s -> %j", (name, labels) => {
    expect(guessToolLabels(name)).toEqual(labels);
  });
});

describe("validateSchema", () => {
  it.each([
    [{ type: "string" }, "a", true],
    [{ type: "string" }, 1, false],
    [{ type: ["string", "null"] }, null, true],
    [{ type: "integer" }, 1, true],
    [{ type: "integer" }, 1.5, false],
    [{ type: "number" }, 1.5, true],
    [{ type: "object" }, [], false],
    [{ type: "array" }, [], true],
    [{ type: "boolean" }, "true", false],
    [{ type: "string", nullable: true }, null, true],
    [{ type: "STRING" }, "Google's uppercase types", true],
    [{ type: "TYPE_UNSPECIFIED" }, 1, true],
    [true, 1, true],
    [false, 1, false],
    [{ enum: ["a", { b: [1] }] }, { b: [1] }, true],
    [{ enum: ["a", { b: [1] }] }, { b: [2] }, false],
    [{ const: { a: 1, b: 2 } }, { b: 2, a: 1 }, true],
    [{ const: 1 }, 2, false],
    [{ minLength: 2 }, "😀", false],
    [{ maxLength: 1 }, "😀", true],
    [{ minimum: 1, maximum: 3 }, 3, true],
    [{ maximum: 3, exclusiveMaximum: true }, 3, false],
    [{ exclusiveMinimum: 1 }, 1, false],
    [{ minItems: 1, maxItems: 2 }, [1, 2, 3], false],
    [{ items: { type: "string" } }, ["a", 1], false],
    [{ items: [{ type: "string" }, { type: "number" }] }, ["a", 1, true], true],
    [{ anyOf: [{ type: "string" }, { type: "number" }] }, 1, true],
    [{ anyOf: [{ type: "string" }, { type: "number" }] }, true, false],
    [{ oneOf: [{ minimum: 1 }, { maximum: 5 }] }, 3, false],
    [{ oneOf: [{ minimum: 1 }, { maximum: 5 }] }, 7, true],
    [{ allOf: [{ minimum: 1 }, { maximum: 5 }] }, 7, false],
    [{ not: { type: "string" } }, "a", false],
    [{ format: "email", multipleOf: 3, unknownKeyword: {} }, 4, true],
    [{ minimum: 1 }, "not a number", true],
  ])("%j with %j: valid %s", (schema, value, valid) => {
    expect(validateSchema(schema, value).length === 0).toBe(valid);
  });

  it("checks required, properties, and additionalProperties", () => {
    const schema = {
      type: "object",
      properties: { a: { type: "string" }, "b c": { type: "number" } },
      required: ["a", "missing"],
      additionalProperties: { type: "number" },
    };

    expect(
      validateSchema(schema, { a: 1, "b c": "x", extra: "y", other: 2 })
    ).toEqual([
      { path: "$.missing", keyword: "required", message: "is required" },
      { path: "$.a", keyword: "type", message: "must be string" },
      { path: '$["b c"]', keyword: "type", message: "must be number" },
      { path: "$.*", keyword: "type", message: "must be number" },
    ]);
  });

  it("does not decide which keys are additional when patternProperties is present", () => {
    const schema = {
      type: "object",
      patternProperties: { "^x-": { type: "string" } },
      additionalProperties: false,
    };
    expect(validateSchema(schema, { "x-a": "1", b: 2 })).toEqual([]);
  });

  it("treats a property set to undefined as missing", () => {
    expect(
      validateSchema(
        { required: ["a"], additionalProperties: false },
        { a: undefined }
      )
    ).toEqual([{ path: "$.a", keyword: "required", message: "is required" }]);
  });

  it("reports at most max violations", () => {
    const schema = { items: { type: "string" } };
    expect(validateSchema(schema, [1, 2, 3, 4, 5, 6, 7], 3)).toHaveLength(3);
  });

  it("follows $ref to $defs, definitions, the root, and escaped pointers", () => {
    const schema = {
      type: "object",
      properties: {
        user: { $ref: "#/$defs/user" },
        tags: { $ref: "#/definitions/a~1b" },
        child: { $ref: "#" },
      },
      $defs: { user: { type: "object", required: ["id"] } },
      definitions: { "a/b": { type: "array", items: { type: "string" } } },
    };

    expect(
      validateSchema(schema, { user: { id: 1 }, tags: ["x"], child: {} })
    ).toEqual([]);
    expect(validateSchema(schema, { user: {}, tags: [1] })).toEqual([
      { path: "$.user.id", keyword: "required", message: "is required" },
      { path: "$.tags[0]", keyword: "type", message: "must be string" },
    ]);
    expect(validateSchema(schema, { child: { child: { user: 1 } } })).toEqual([
      {
        path: "$.child.child.user",
        keyword: "type",
        message: "must be object",
      },
    ]);
  });

  it("ignores a $ref it can't resolve", () => {
    expect(
      validateSchema(
        { $ref: "https://example.invalid/schema.json", type: "string" },
        "a"
      )
    ).toEqual([]);
    expect(validateSchema({ $ref: "#/$defs/missing" }, 1)).toEqual([]);
  });

  it("stops a $ref cycle that makes no progress", () => {
    const schema = { $defs: { a: { $ref: "#/$defs/a" } }, $ref: "#/$defs/a" };

    expect(validateSchema(schema, 1)).toEqual([
      {
        path: "$",
        keyword: "$ref",
        message: "follows $ref more than 32 deep",
      },
    ]);
  });

  it("stops a branching $ref cycle within its step budget", () => {
    const schema = {
      $defs: {
        a: { anyOf: [{ $ref: "#/$defs/a" }, { $ref: "#/$defs/a" }] },
      },
      $ref: "#/$defs/a",
    };
    const start = performance.now();

    expect(validateSchema(schema, {})).toEqual([
      { path: "$", keyword: "budget", message: "is too complex to validate" },
    ]);
    expect(performance.now() - start).toBeLessThan(5000);
  });

  it("stops at 64 levels of nesting in the arguments", () => {
    let schema: Record<string, unknown> = { type: "object" };
    let value: Record<string, unknown> = {};
    for (let i = 0; i < 100; i++) {
      schema = { type: "object", properties: { child: schema } };
      value = { child: value };
    }

    expect(validateSchema(schema, value)).toEqual([
      {
        path: `$${".child".repeat(65)}`,
        keyword: "depth",
        message: "is nested deeper than 64 levels",
      },
    ]);
  });

  it("follows a recursive $ref at most 32 deep", () => {
    const schema = { type: "object", properties: { child: { $ref: "#" } } };
    const nest = (levels: number) => {
      let value: Record<string, unknown> = {};
      for (let i = 0; i < levels; i++) {
        value = { child: value };
      }
      return value;
    };

    expect(validateSchema(schema, nest(32))).toEqual([]);
    expect(validateSchema(schema, nest(33))[0]?.keyword).toBe("$ref");
  });
});

describe("pattern", () => {
  it("checks a pattern, and reports the path but not the value", () => {
    const schema = { type: "string", pattern: "^[a-z]+@acme\\.example$" };

    expect(validateSchema(schema, "ops@acme.example")).toEqual([]);
    expect(validateSchema(schema, TOKEN)).toEqual([
      { path: "$", keyword: "pattern", message: "must match the pattern" },
    ]);
  });

  it.each([
    ["nested quantifiers", "^(a+)+$"],
    ["overlapping alternation", "^(a|aa)*$"],
    ["a quantified group with a bounded inner quantifier", "^(\\d{1,3})+$"],
    ["a wide bounded repeat of an unbounded group", "^(a+){2,20}$"],
    ["a backreference", "^(a*)\\1$"],
    ["a named backreference", "^(?<x>a*)\\k<x>$"],
    [
      "Zod's email pattern",
      "^(?:[A-Za-z0-9_'+\\-]+\\.)*[A-Za-z0-9_'+\\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\\-]*\\.)+[A-Za-z]{2,}$",
    ],
  ])("does not run a pattern with %s", (_, pattern) => {
    const start = performance.now();

    expect(planPattern(pattern)).toBeNull();
    expect(validateSchema({ pattern }, `${"a".repeat(50_000)}!`)).toEqual([]);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it.each([
    ["^[a-z0-9-]+$", 1, 1_048_576],
    ["^\\d{1,3}(\\.\\d{1,3}){3}$", 0, 1_048_576],
    ["[a-z]+", 2, 1024],
    ["^\\d*\\d*x$", 2, 1024],
    ["^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", 3, 101],
    ["^\\d{1,100}\\d*$", 2, 1024],
    ["^a|b+", 2, 1024],
  ])("runs %s on strings up to 2^(20/%i) characters", (pattern, degree, max) => {
    expect(planPattern(pattern)).toMatchObject({ degree, maxLength: max });
  });

  it("fails a string too long to check, and bounds the work below that", () => {
    const schema = { pattern: "^\\d*\\d*\\d*x$" };
    const plan = planPattern(schema.pattern);
    const max = plan?.maxLength ?? 0;
    const start = performance.now();

    expect(validateSchema(schema, "1".repeat(max))).toEqual([
      { path: "$", keyword: "pattern", message: "must match the pattern" },
    ]);
    expect(performance.now() - start).toBeLessThan(1000);
    expect(validateSchema(schema, "1".repeat(max + 1))).toEqual([
      {
        path: "$",
        keyword: "pattern",
        message: `is too long to check against its pattern (over ${max} characters)`,
      },
    ]);
  });

  it("runs an anchored single-quantifier pattern on a long string", () => {
    expect(
      validateSchema({ pattern: "^[a-z]+$" }, "a".repeat(100_000))
    ).toEqual([]);
  });

  it("ignores an invalid pattern, and accepts one written without the u flag", () => {
    expect(validateSchema({ pattern: "([a-z]" }, "1")).toEqual([]);
    expect(validateSchema({ pattern: "^a\\-b$" }, "a-b")).toEqual([]);
    expect(validateSchema({ pattern: "^a\\-b$" }, "a_b")).toHaveLength(1);
  });
});

describe("ToolPolicyError", () => {
  it("carries the tool, reason, and violations", () => {
    const decision = createToolPolicy({ tools: [SEND_EMAIL] }).check({
      name: "send_email",
      arguments: { to: 1, body: "b" },
    });
    const error = new ToolPolicyError(decision);

    expect(error).toMatchObject({
      name: "ToolPolicyError",
      code: "TOOL_POLICY_VIOLATION",
      tool: "send_email",
      reason: "invalid_arguments",
      violations: [{ path: "$.to", keyword: "type" }],
      message: decision.message,
    });
    expect(
      new ToolPolicyError({ tool: "x", reason: "denied_tool", message: "m" })
        .violations
    ).toEqual([]);
  });
});
