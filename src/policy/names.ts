/**
 * Tool names: glob matching for allow lists, deny lists, and rules, and the
 * opt-in guess of a tool's labels from its name.
 */

import { identifierWords } from "../tools";

/**
 * What a tool does with data, for the flow rule. `untrusted`: its results
 * carry content from outside, such as a web page, an email, or an issue.
 * `private`: it reads private data. `sink`: it can send data out, such as
 * by sending an email or a request, or by posting where others can read.
 */
export type ToolLabel = "untrusted" | "private" | "sink";

/**
 * Whether `name` matches `pattern`, where `*` matches any run of characters,
 * including none, and every other character matches itself.
 */
export function globMatch(pattern: string, name: string): boolean {
  if (!pattern.includes("*")) {
    return pattern === name;
  }
  let p = 0;
  let n = 0;
  let star = -1;
  let resume = 0;
  while (n < name.length) {
    if (p < pattern.length && pattern[p] === "*") {
      star = p;
      p += 1;
      resume = n;
    } else if (p < pattern.length && pattern[p] === name[n]) {
      p += 1;
      n += 1;
    } else if (star === -1) {
      return false;
    } else {
      p = star + 1;
      resume += 1;
      n = resume;
    }
  }
  while (p < pattern.length && pattern[p] === "*") {
    p += 1;
  }
  return p === pattern.length;
}

const FETCH_VERBS = new Set(["fetch", "browse", "scrape", "crawl", "download"]);
const READ_VERBS = new Set([
  ...FETCH_VERBS,
  "get",
  "read",
  "list",
  "search",
  "find",
  "query",
  "view",
  "open",
  "retrieve",
  "lookup",
  "load",
]);
const SEND_VERBS = new Set([
  "send",
  "post",
  "publish",
  "upload",
  "share",
  "forward",
  "reply",
  "notify",
  "submit",
  "comment",
]);
const CREATE_VERBS = new Set(["create", "add", "write"]);
const VERBS = new Set([...READ_VERBS, ...SEND_VERBS, ...CREATE_VERBS]);

/** Things whose content comes from outside: whoever wrote the page, email, or issue. */
const OUTSIDE_NOUNS = new Set([
  "url",
  "web",
  "webpage",
  "website",
  "http",
  "https",
  "email",
  "emails",
  "mail",
  "inbox",
  "message",
  "messages",
  "issue",
  "issues",
  "comment",
  "comments",
  "pr",
  "prs",
  "pull",
  "discussion",
  "discussions",
  "ticket",
  "tickets",
  "tweet",
  "tweets",
  "post",
  "posts",
  "feed",
  "rss",
  "news",
  "review",
  "reviews",
  "notification",
  "notifications",
]);
const PRIVATE_NOUNS = new Set([
  "email",
  "emails",
  "mail",
  "inbox",
  "message",
  "messages",
  "file",
  "files",
  "document",
  "documents",
  "doc",
  "docs",
  "note",
  "notes",
  "drive",
  "contact",
  "contacts",
  "calendar",
  "event",
  "events",
  "customer",
  "customers",
  "user",
  "users",
  "account",
  "accounts",
  "record",
  "records",
  "database",
  "table",
  "tables",
  "secret",
  "secrets",
  "password",
  "passwords",
  "credential",
  "credentials",
]);
/** Things that others can read once created. */
const PUBLIC_NOUNS = new Set([
  "issue",
  "comment",
  "pr",
  "pull",
  "gist",
  "discussion",
  "post",
  "message",
  "email",
  "tweet",
  "review",
  "release",
  "webhook",
]);
const HTTP_SEND_WORDS = new Set(["post", "put", "patch", "request"]);

/**
 * Guesses a tool's labels from its name. It is deliberately narrow, so many
 * tools get no label; check what it returns for your tools, and set labels
 * yourself where it is wrong. The name is split into lowercase words (at
 * `_`, `-`, `.`, spaces, and camelCase), and the verb is the first word that
 * is one of the verbs below, so a prefix such as `github_` or `slack_` is
 * skipped.
 *
 * - `untrusted`: the verb is fetch, browse, scrape, crawl, or download; or it
 *   reads (get, read, list, search, find, query, view, open, retrieve,
 *   lookup, load) and the name has a word for outside content, such as url,
 *   web, email, inbox, message, issue, comment, pr, pull, ticket, post, or
 *   review; or the name has the words http and request.
 * - `private`: the verb reads, and the name has a word for private data,
 *   such as email, inbox, message, file, document, note, contact, calendar,
 *   customer, user, account, record, database, secret, or password.
 * - `sink`: the verb is send, post, publish, upload, share, forward, reply,
 *   notify, submit, or comment; or it is create, add, or write, and the name
 *   has a word for something others read, such as issue, comment, pr, pull,
 *   gist, post, message, email, review, or release; or the name has the word
 *   webhook and the verb doesn't read; or it has the word http and one of
 *   post, put, patch, or request.
 */
export function guessToolLabels(name: string): ToolLabel[] {
  const words = identifierWords(name).toLowerCase().split(" ").filter(Boolean);
  const verb = words.find((word) => VERBS.has(word)) ?? "";
  const has = (set: Set<string>): boolean => words.some((w) => set.has(w));
  const reads = READ_VERBS.has(verb);
  const http = words.includes("http") || words.includes("https");
  const labels: ToolLabel[] = [];
  if (
    FETCH_VERBS.has(verb) ||
    (reads && has(OUTSIDE_NOUNS)) ||
    (http && words.includes("request"))
  ) {
    labels.push("untrusted");
  }
  if (reads && has(PRIVATE_NOUNS)) {
    labels.push("private");
  }
  if (
    SEND_VERBS.has(verb) ||
    (CREATE_VERBS.has(verb) && has(PUBLIC_NOUNS)) ||
    (words.includes("webhook") && !reads) ||
    (http && has(HTTP_SEND_WORDS))
  ) {
    labels.push("sink");
  }
  return labels;
}
