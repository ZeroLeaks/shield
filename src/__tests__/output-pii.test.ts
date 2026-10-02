import { describe, expect, it } from "vitest";
import {
  DEFAULT_PII_KINDS,
  detectPII,
  ibanChecksumValid,
  luhnValid,
  type PIIKind,
} from "../output/pii";
import type { OutputFinding } from "../output/types";

const ALL_KINDS: PIIKind[] = [
  ...DEFAULT_PII_KINDS,
  "ip_address",
  "uk_nino",
  "us_passport",
];

function kinds(text: string, kindList: PIIKind[] = ALL_KINDS): string[] {
  return detectPII(text, { kinds: kindList }).map((f) => f.kind);
}

function only(text: string, kind: PIIKind): OutputFinding[] {
  return detectPII(text, { kinds: [kind] });
}

/** Independent Luhn completion (does not use the code under test). */
function withLuhnDigit(body: string): string {
  for (let d = 0; d <= 9; d++) {
    const candidate = `${body}${d}`;
    const reversed = candidate.split("").reverse();
    let sum = 0;
    for (let i = 0; i < reversed.length; i++) {
      let digit = Number(reversed[i]);
      if (i % 2 === 1) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }
      sum += digit;
    }
    if (sum % 10 === 0) {
      return candidate;
    }
  }
  throw new Error("unreachable");
}

const GROUPS_OF_FOUR = /(.{4})/g;

function group(number: string): string {
  return number.replace(GROUPS_OF_FOUR, "$1 ").trim();
}

/** Builds a valid IBAN with BigInt mod-97 (independent of the code under test). */
function makeIban(country: string, bban: string): string {
  const numeric = `${bban}${country}00`
    .split("")
    .map((c) => (c >= "A" ? String(c.charCodeAt(0) - 55) : c))
    .join("");
  const check = 98n - (BigInt(numeric) % 97n);
  return `${country}${String(check).padStart(2, "0")}${bban}`;
}

describe("email", () => {
  it("flags personal addresses and masks the preview", () => {
    const [finding] = only(
      "Reach Jane at jane.smith@acme-corp.io today.",
      "email"
    );
    expect(finding.severity).toBe("medium");
    expect(finding.confidence).toBeGreaterThanOrEqual(0.9);
    expect(finding.preview).toBe("j***@acme-corp.io");
  });

  it("flags example.com and placeholder addresses at confidence 0.3", () => {
    for (const address of [
      "user@example.com",
      "john.doe@acme.test",
      "someone@example.org",
    ]) {
      const [finding] = only(`Email ${address} for access.`, "email");
      expect(finding.severity, address).toBe("low");
      expect(finding.confidence, address).toBe(0.3);
    }
  });

  it("treats role accounts as low", () => {
    const [finding] = only("Write to support@acme-corp.io.", "email");
    expect(finding.severity).toBe("low");
  });

  it("skips things that only look like addresses", () => {
    const benign = [
      "git clone git@github.com:acme/repo.git",
      "npm install lodash@4.17.21 react@latest",
      "import type { Node } from '@types/node'",
      "background: url(icon@2x.png)",
      "ssh deploy@localhost",
      "@app.route('/users')",
      "https://user@internal.acme.dev/path",
      "Contact: @jane on Slack",
    ];
    for (const text of benign) {
      expect(only(text, "email"), text).toEqual([]);
    }
  });

  it("accepts mailto: links", () => {
    expect(
      only("<a href='mailto:jane@acme-corp.io'>mail</a>", "email")
    ).toHaveLength(1);
  });
});

describe("phone", () => {
  it("detects common NANP and international formats", () => {
    const numbers = [
      "(415) 867-5309",
      "415-867-5309",
      "415.867.5309",
      "1-415-867-5309",
      "+1 415 867 5309",
      "+14158675309",
      "+44 20 7946 0958",
      "+49 30 12849376",
      "+33 6 12 45 78 90",
    ];
    for (const number of numbers) {
      const text = `You can reach me at ${number} after 5pm.`;
      const findings = only(text, "phone");
      expect(findings, number).toHaveLength(1);
      expect(text.slice(findings[0].start, findings[0].end)).toBe(number);
      expect(findings[0].severity).toBe("medium");
      expect(findings[0].preview.endsWith(number.slice(-2))).toBe(true);
      expect(findings[0].preview).not.toBe(number);
    }
  });

  it("needs a phone word for unformatted and domestic numbers", () => {
    expect(only("Call me: 4158675309", "phone")).toHaveLength(1);
    expect(only("Tel: 020 7946 0958", "phone")).toHaveLength(1);
    expect(only("The id is 4158675309", "phone")).toEqual([]);
    expect(only("Totals were 020 7946 0958 units", "phone")).toEqual([]);
  });

  it("marks fictional 555 numbers low", () => {
    const [finding] = only("Call (555) 123-4567 for a demo.", "phone");
    expect(finding.severity).toBe("low");
    expect(finding.confidence).toBe(0.3);
  });

  it("finds a phone number inside a longer run of numbers", () => {
    const text = "Call 415 867 5309 2 times a day";
    const findings = only(text, "phone");
    expect(findings.map((f) => text.slice(f.start, f.end))).toEqual([
      "415 867 5309",
    ]);
  });

  it("does not match versions, dates, ids, hashes, math, or money", () => {
    const benign = [
      "Upgrade to version 1.2.3 or 10.4.22.1 today.",
      "Released on 2024-01-15 at 12:30:45 UTC (2024/01/15).",
      "ISBN 978-3-16-148410-0 and ISBN-10 0-306-40615-2.",
      "Request 550e8400-e29b-41d4-a716-446655440000 failed.",
      "Commit 3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a fixed it.",
      "pi is about 3.14159265358979 and e is 2.718281828459045.",
      "The timestamp 1700000000 and 1700000000123 are in seconds and ms.",
      "Order #415-867-5309 has shipped; ref: 415-867-5309.",
      "Invalid area codes like 123-456-7890 are not numbers.",
      "Revenue was $1,234,567.89 and 10,000,000 units.",
      "Counting: 1 2 3 4 5 6 7 8 9 10 11 12",
      "Server 192.168.1.100 answered in 0.25 s.",
      "Coordinates 37.7749, -122.4194.",
    ];
    for (const text of benign) {
      expect(only(text, "phone"), text).toEqual([]);
    }
  });
});

describe("credit_card", () => {
  const visa = withLuhnDigit("453201511283036");
  const mastercard = withLuhnDigit("524187640382719");
  const amex = withLuhnDigit("37828224631741");

  it("detects grouped cards as high and masks all but the last four", () => {
    const text = `Card: ${group(visa)} exp 12/27`;
    const [finding] = only(text, "credit_card");
    expect(finding.severity).toBe("high");
    expect(text.slice(finding.start, finding.end)).toBe(group(visa));
    expect(finding.preview).toBe(`**** **** **** ${visa.slice(-4)}`);
  });

  it("detects Mastercard and Amex layouts", () => {
    expect(only(`mc ${group(mastercard)}`, "credit_card")).toHaveLength(1);
    const amexGrouped = `${amex.slice(0, 4)} ${amex.slice(4, 10)} ${amex.slice(10)}`;
    expect(only(`amex ${amexGrouped}`, "credit_card")).toHaveLength(1);
  });

  it("rates unseparated numbers by context", () => {
    expect(only(`Pay with ${visa}`, "credit_card")[0].severity).toBe("medium");
    expect(only(`Visa card number ${visa}`, "credit_card")[0].severity).toBe(
      "high"
    );
    expect(only(`transaction id ${visa}`, "credit_card")).toEqual([]);
  });

  it("marks well-known test cards low", () => {
    const [finding] = only(
      "Use 4242 4242 4242 4242 in test mode.",
      "credit_card"
    );
    expect(finding.severity).toBe("low");
    expect(finding.confidence).toBe(0.3);
    expect(finding.preview).toBe("**** **** **** 4242");
  });

  it("requires a valid Luhn digit, network, and grouping", () => {
    const badLuhn = `${visa.slice(0, -1)}${(Number(visa.slice(-1)) + 1) % 10}`;
    expect(only(group(badLuhn), "credit_card")).toEqual([]);
    expect(
      only(group(withLuhnDigit("123456789012345")), "credit_card")
    ).toEqual([]);
    const mixed = `${visa.slice(0, 4)}-${visa.slice(4, 8)} ${visa.slice(8, 12)}-${visa.slice(12)}`;
    expect(only(mixed, "credit_card")).toEqual([]);
  });

  it("finds two cards in a row", () => {
    const text = `${group(visa)} ${group(mastercard)}`;
    expect(only(text, "credit_card")).toHaveLength(2);
  });

  it("exports a Luhn check", () => {
    expect(luhnValid(visa)).toBe(true);
    expect(luhnValid("4242424242424241")).toBe(false);
  });
});

describe("us_ssn", () => {
  it("detects hyphenated SSNs, higher with context", () => {
    expect(only("Applicant 536-22-1234 approved", "us_ssn")[0].confidence).toBe(
      0.7
    );
    const [withContext] = only("SSN: 536-22-1234", "us_ssn");
    expect(withContext.confidence).toBe(0.95);
    expect(withContext.preview).toBe("***-**-1234");
  });

  it("needs context for spaced or unseparated SSNs", () => {
    expect(only("Social Security Number 536 22 1234", "us_ssn")).toHaveLength(
      1
    );
    expect(only("ssn=536221234", "us_ssn")).toHaveLength(1);
    expect(only("Values 536 22 1234", "us_ssn")).toEqual([]);
    expect(only("Batch 536221234", "us_ssn")).toEqual([]);
  });

  it("rejects impossible SSNs and marks well-known examples low", () => {
    for (const bad of [
      "000-12-3456",
      "666-12-3456",
      "912-12-3456",
      "536-00-1234",
      "536-22-0000",
    ]) {
      expect(only(`SSN ${bad}`, "us_ssn"), bad).toEqual([]);
    }
    expect(only("SSN 123-45-6789", "us_ssn")[0].severity).toBe("low");
    expect(only("SSN 078-05-1120", "us_ssn")[0].severity).toBe("low");
  });
});

describe("iban", () => {
  const german = makeIban("DE", "370400440532013987");
  const french = makeIban("FR", "20041010050500013M02606");

  it("detects valid IBANs, compact or grouped", () => {
    expect(ibanChecksumValid(german)).toBe(true);
    const [compact] = only(`IBAN: ${german}`, "iban");
    expect(compact.severity).toBe("high");
    expect(compact.preview.startsWith("DE")).toBe(true);
    expect(compact.preview.endsWith(german.slice(-4))).toBe(true);
    expect(compact.preview).not.toContain(german.slice(4, 12));
    expect(only(`IBAN ${group(french)}`, "iban")).toHaveLength(1);
  });

  it("rejects bad checksums and wrong lengths", () => {
    const broken = `${german.slice(0, -1)}${german.endsWith("0") ? "1" : "0"}`;
    expect(only(broken, "iban")).toEqual([]);
    expect(only(`${german}12`, "iban")).toEqual([]);
  });

  it("marks well-known example IBANs low", () => {
    expect(only("DE89370400440532013000", "iban")[0].severity).toBe("low");
  });
});

describe("opt-in kinds", () => {
  it("does not report IPs, NINOs, or passports by default", () => {
    const text =
      "Server 203.0.114.7, NINO HT 71 84 52 C, passport number 548213967";
    expect(detectPII(text)).toEqual([]);
  });

  it("flags public IPv4 addresses only", () => {
    const text =
      "Hosts: 203.0.114.7, 10.0.0.1, 192.168.1.1, 172.16.4.2, 127.0.0.1, 100.64.0.1, 192.0.2.10, 224.0.0.1";
    const findings = only(text, "ip_address");
    expect(findings.map((f) => text.slice(f.start, f.end))).toEqual([
      "203.0.114.7",
    ]);
    expect(findings[0].preview).toBe("203.0.*.*");
    expect(
      only("DNS 8.8.8.8 and 1.1.1.1", "ip_address").every(
        (f) => f.severity === "low"
      )
    ).toBe(true);
    expect(only("Upgrade to version 1.2.3.4 now", "ip_address")).toEqual([]);
  });

  it("flags UK National Insurance numbers", () => {
    const [finding] = only(
      "National Insurance number: HT 71 84 52 C",
      "uk_nino"
    );
    expect(finding.confidence).toBe(0.95);
    expect(only("NINO QQ123456C", "uk_nino")).toEqual([]);
  });

  it("flags passport numbers only next to the word passport", () => {
    expect(only("Passport number: 548213967", "us_passport")).toHaveLength(1);
    expect(only("Tracking number: 548213967", "us_passport")).toEqual([]);
  });
});

describe("options", () => {
  it("defaults to email, phone, credit_card, us_ssn, iban", () => {
    expect(DEFAULT_PII_KINDS).toEqual([
      "email",
      "phone",
      "credit_card",
      "us_ssn",
      "iban",
    ]);
    const text = "jane.smith@acme-corp.io (415) 867-5309 203.0.114.7";
    expect(kinds(text, [...DEFAULT_PII_KINDS])).toEqual(["email", "phone"]);
  });

  it("filters by minConfidence", () => {
    const text = "user@example.com and jane.smith@acme-corp.io";
    expect(
      detectPII(text, { minConfidence: 0.5 }).map((f) =>
        text.slice(f.start, f.end)
      )
    ).toEqual(["jane.smith@acme-corp.io"]);
  });

  it("returns [] for empty and non-string input", () => {
    expect(detectPII("")).toEqual([]);
    expect(detectPII(null as unknown as string)).toEqual([]);
  });

  it("never puts a full value in a preview", () => {
    const visa = withLuhnDigit("453201511283036");
    const text = `jane.smith@acme-corp.io ${group(visa)} SSN 536-22-1234 (415) 867-5309 ${makeIban("DE", "370400440532013987")}`;
    for (const finding of detectPII(text)) {
      const value = text.slice(finding.start, finding.end);
      expect(finding.preview, finding.kind).not.toBe(value);
      expect(finding.preview.includes(value)).toBe(false);
    }
  });
});
