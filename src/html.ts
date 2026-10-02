/**
 * Reads an HTML page the way an agent reading it would: text, comments, and
 * descriptive attributes, without scripts, styles, or markup. Text inside
 * hidden elements is also collected on its own, since text a person can't see
 * is where instructions for an AI are usually planted.
 *
 * A single linear pass with no backtracking, so any input is safe to scan.
 */

/** Attributes whose values a person or an agent can read. `data-*` counts too. */
const TEXT_ATTRIBUTES = new Set([
  "alt",
  "title",
  "aria-label",
  "placeholder",
  "value",
  "content",
  "label",
  "summary",
]);

/** Elements whose content is never shown or read as text. */
const SKIPPED = new Set(["script", "style", "noscript", "template"]);

/** Elements without a closing tag. */
const VOID = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr",
]);

const RE_TAG = /<\/?[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?\/?>/g;
/** The same, anchored where it starts, so each "<" is tried once. */
const RE_TAG_AT = new RegExp(RE_TAG.source, "y");
const RE_ATTR =
  /([^\s"'=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
const RE_HIDDEN_STYLE =
  /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])|opacity\s*:\s*0(?![.\d]*[1-9])/i;
const RE_ENTITY = /&(?:#(\d{1,7})|#x([0-9a-fA-F]{1,6})|([a-zA-Z]{2,8}));/g;
/** The named entities common on web pages; others are left as written. */
const NAMED: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  copy: "\u00a9",
  reg: "\u00ae",
  trade: "\u2122",
  hellip: "\u2026",
  mdash: "\u2014",
  ndash: "\u2013",
  lsquo: "\u2018",
  rsquo: "\u2019",
  ldquo: "\u201c",
  rdquo: "\u201d",
  laquo: "\u00ab",
  raquo: "\u00bb",
  bull: "\u2022",
  middot: "\u00b7",
  times: "\u00d7",
  deg: "\u00b0",
  euro: "\u20ac",
  pound: "\u00a3",
  yen: "\u00a5",
  cent: "\u00a2",
  sect: "\u00a7",
  para: "\u00b6",
  zwnj: "\u200c",
  zwj: "\u200d",
  shy: "\u00ad",
};
/**
 * Open elements tracked, and how far back a closing tag looks for its
 * opening tag, so malformed markup can't make the pass quadratic.
 */
const MAX_OPEN = 256;
const MAX_CLOSE_SEARCH = 32;
/**
 * HTML elements that mark input as a page or an HTML email. Tags with other
 * names, such as the `<rule>` or `<instructions>` some prompts use, don't count.
 */
const HTML_ELEMENTS = new Set([
  "html",
  "head",
  "body",
  "div",
  "span",
  "p",
  "a",
  "table",
  "tr",
  "td",
  "th",
  "tbody",
  "thead",
  "ul",
  "ol",
  "li",
  "img",
  "meta",
  "link",
  "script",
  "style",
  "section",
  "article",
  "header",
  "footer",
  "nav",
  "main",
  "aside",
  "form",
  "input",
  "button",
  "label",
  "select",
  "option",
  "textarea",
  "iframe",
  "svg",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "br",
  "hr",
  "strong",
  "em",
  "b",
  "i",
  "u",
  "small",
  "font",
  "center",
  "pre",
  "blockquote",
  "figure",
  "figcaption",
  "time",
  "dl",
  "dt",
  "dd",
  "noscript",
  "picture",
  "source",
  "video",
  "canvas",
]);
/** HTML element tags needed before input is treated as HTML. */
const TAGS_FOR_HTML = 8;
const SNIFF_CHARS = 20_000;

export interface HtmlText {
  /** Everything an agent could read, one piece per line. */
  text: string;
  /** Only the text of hidden elements and comments. */
  hidden: string;
}

/** Whether `input` is HTML markup rather than text that mentions a tag or two. */
export function looksLikeHtml(input: string): boolean {
  const head = input.length > SNIFF_CHARS ? input.slice(0, SNIFF_CHARS) : input;
  RE_TAG.lastIndex = 0;
  let tags = 0;
  let m = RE_TAG.exec(head);
  while (m) {
    if (HTML_ELEMENTS.has(tagName(m[0]))) {
      tags++;
      if (tags >= TAGS_FOR_HTML) {
        return true;
      }
    }
    m = RE_TAG.exec(head);
  }
  return false;
}

function decodeEntities(s: string): string {
  if (!s.includes("&")) {
    return s;
  }
  return s.replace(RE_ENTITY, (whole, dec, hex, name) => {
    if (dec || hex) {
      const code = Number.parseInt(dec ?? hex, dec ? 10 : 16);
      return code > 0 && code <= 0x10_ff_ff
        ? String.fromCodePoint(code)
        : whole;
    }
    return NAMED[name.toLowerCase()] ?? whole;
  });
}

const RE_NAME_END = /[\s/>]/;
const RE_LINK_VALUE = /^(?:#|http|\/)/;
const RE_TAG_NAME = /^<\/?([a-zA-Z][a-zA-Z0-9-]*)/;

interface Attributes {
  readable: string[];
  hidden: boolean;
}

/** Whether an attribute hides its element. */
function hides(name: string, value: string): boolean {
  if (name === "hidden") {
    return true;
  }
  if (name === "aria-hidden") {
    return value === "true";
  }
  return name === "style" && RE_HIDDEN_STYLE.test(value);
}

/** Whether an attribute's value is text a person or an agent reads. */
function readable(name: string, value: string): boolean {
  return (
    (TEXT_ATTRIBUTES.has(name) || name.startsWith("data-")) &&
    value.length > 2 &&
    !RE_LINK_VALUE.test(value)
  );
}

function readAttributes(tag: string): Attributes {
  const out: Attributes = { readable: [], hidden: false };
  const nameEnd = tag.search(RE_NAME_END);
  const rest = nameEnd < 0 ? "" : tag.slice(nameEnd);
  RE_ATTR.lastIndex = 0;
  let m: RegExpExecArray | null = RE_ATTR.exec(rest);
  while (m) {
    const name = m[1].toLowerCase();
    const value = decodeEntities(m[2] ?? m[3] ?? m[4] ?? "");
    if (hides(name, value)) {
      out.hidden = true;
    } else if (readable(name, value)) {
      out.readable.push(value.trim());
    }
    m = RE_ATTR.exec(rest);
  }
  return out;
}

function tagName(tag: string): string {
  const m = RE_TAG_NAME.exec(tag);
  return m ? m[1].toLowerCase() : "";
}

/** Finds `</name` after `from`, case-insensitively; -1 if absent. */
function closingTag(html: string, name: string, from: number): number {
  const lower = `</${name}`;
  let i = html.indexOf("</", from);
  while (i >= 0) {
    if (html.slice(i, i + lower.length).toLowerCase() === lower) {
      return i;
    }
    i = html.indexOf("</", i + 2);
  }
  return -1;
}

/** What has been read so far, and the elements still open. */
class Reader {
  readonly text: string[] = [];
  readonly hidden: string[] = [];
  /** Open elements, and whether each one hides its content. */
  private readonly open: Array<{ name: string; hidden: boolean }> = [];
  private hiddenDepth = 0;

  get inHidden(): boolean {
    return this.hiddenDepth > 0;
  }

  add(piece: string, isHidden = this.inHidden): void {
    const t = decodeEntities(piece).trim();
    if (t) {
      this.text.push(t);
      if (isHidden) {
        this.hidden.push(t);
      }
    }
  }

  /** Closes the nearest open element with this name, and any opened inside it. */
  close(name: string): void {
    const stop = Math.max(0, this.open.length - MAX_CLOSE_SEARCH);
    for (let k = this.open.length - 1; k >= stop; k--) {
      if (this.open[k].name === name) {
        for (const closed of this.open.splice(k)) {
          if (closed.hidden) {
            this.hiddenDepth--;
          }
        }
        return;
      }
    }
  }

  enter(name: string, hidden: boolean): void {
    if (this.open.length >= MAX_OPEN) {
      return;
    }
    this.open.push({ name, hidden });
    if (hidden) {
      this.hiddenDepth++;
    }
  }
}

/** Reads the tag at `html[lt]` and returns where reading continues. */
function readTag(html: string, lt: number, reader: Reader): number {
  if (html.startsWith("<!--", lt)) {
    const end = html.indexOf("-->", lt + 4);
    reader.add(html.slice(lt + 4, end < 0 ? html.length : end), true);
    return end < 0 ? html.length : end + 3;
  }
  RE_TAG_AT.lastIndex = lt;
  const m = RE_TAG_AT.exec(html);
  if (!m) {
    // A lone "<" in text.
    reader.add("<");
    return lt + 1;
  }
  const tag = m[0];
  const name = tagName(tag);
  const next = lt + tag.length;
  if (tag.startsWith("</")) {
    reader.close(name);
    return next;
  }
  const attrs = readAttributes(tag);
  for (const value of attrs.readable) {
    reader.add(value, attrs.hidden || reader.inHidden);
  }
  if (SKIPPED.has(name)) {
    const end = closingTag(html, name, next);
    return end < 0 ? html.length : end;
  }
  if (!(VOID.has(name) || tag.endsWith("/>"))) {
    reader.enter(name, attrs.hidden);
  }
  return next;
}

/** The readable text of an HTML page, and separately its hidden text. */
export function htmlText(html: string): HtmlText {
  const reader = new Reader();
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt < 0) {
      reader.add(html.slice(i));
      break;
    }
    if (lt > i) {
      reader.add(html.slice(i, lt));
    }
    i = readTag(html, lt, reader);
  }
  return { text: reader.text.join("\n"), hidden: reader.hidden.join("\n") };
}
