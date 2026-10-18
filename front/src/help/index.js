/**
 * In-app help: one Markdown file per menu page and language (help/<lang>/<menu key>.md), loaded
 * only when the help panel opens, so it adds nothing to the page bundles and works offline.
 *
 * File layout: "# Title", then the summary (shown open), then "## Section" blocks (shown folded).
 */
const FILES = import.meta.glob("./*/*.md", { query: "?raw", import: "default" });

/** Pages that share another page's help (a tab of the same page). */
export const ALIASES = { "system-logs": "audit-trail", "backup-runs": "backup-schedules" };

const helpKey = (key) => ALIASES[key] || key;
const path = (lang, key) => `./${lang}/${helpKey(key)}.md`;

/** Whether the page has help in this language. */
export const hasHelp = (key, lang) => Boolean(FILES[path(lang, key)]);

/** {title, summary, sections: [{title, body}]} of a page, or null. */
export async function loadHelp(key, lang) {
    const load = FILES[path(lang, key)];
    return load ? parseHelp(await load()) : null;
}

const everything = {};

/** Every page's help in one language, [{key, title, summary, sections}], loaded once (for the search). */
export function loadAllHelp(lang) {
    if (!everything[lang]) {
        const prefix = `./${lang}/`;
        everything[lang] = Promise.all(Object.keys(FILES).filter((f) => f.startsWith(prefix)).map(async (f) => (
            { key: f.slice(prefix.length, -3), ...parseHelp(await FILES[f]()) })));
    }
    return everything[lang];
}

/**
 * Help sections matching a search, on the pages in `keys` only: title matches first, then text
 * matches, at most `limit`. Each result is {key, page, section}.
 */
export function searchHelp(pages, needle, keys, limit = 5) {
    const q = needle.trim().toLowerCase();
    if (q.length < 2) return [];
    const allowed = new Set(keys.map(helpKey));
    const inTitle = [];
    const inText = [];
    for (const p of pages) {
        if (!allowed.has(p.key)) continue;
        for (const s of p.sections) {
            if (s.title.toLowerCase().includes(q)) inTitle.push({ key: p.key, page: p.title, section: s.title });
            else if (s.body.toLowerCase().includes(q)) inText.push({ key: p.key, page: p.title, section: s.title });
        }
    }
    return [...inTitle, ...inText].slice(0, limit);
}

export function parseHelp(text) {
    const lines = text.replace(/\r\n/g, "\n").split("\n");
    let title = "";
    const summary = [];
    const sections = [];
    for (const line of lines) {
        if (!title && line.startsWith("# ")) title = line.slice(2).trim();
        else if (line.startsWith("## ")) sections.push({ title: line.slice(3).trim(), body: [] });
        else (sections.length ? sections[sections.length - 1].body : summary).push(line);
    }
    return {
        title,
        summary: summary.join("\n").trim(),
        sections: sections.map((s) => ({ title: s.title, body: s.body.join("\n").trim() })),
    };
}

/**
 * Blocks of a Markdown body: paragraphs, "- " and "1. " lists, "> " notes, "|" tables and ``` code.
 * A block indented under a list item (4 spaces) is read as a block of its own after the list.
 * Rendering builds React elements from these (HelpPanel), never HTML.
 */
export function blocks(body) {
    const out = [];
    const lines = body.split("\n").map((l) => l.replace(/^ {4}/, ""));
    let i = 0;
    const take = (test) => {
        const got = [];
        while (i < lines.length && test(lines[i])) got.push(lines[i++]);
        return got;
    };
    while (i < lines.length) {
        const line = lines[i];
        if (!line.trim()) { i += 1; continue; }
        if (line.startsWith("```")) {
            i += 1;
            const code = take((l) => !l.startsWith("```"));
            i += 1;
            out.push({ type: "pre", text: code.join("\n") });
        } else if (line.startsWith("|")) {
            const rows = take((l) => l.startsWith("|"))
                .filter((l) => !/^\|[\s:|-]+\|$/.test(l))
                .map((l) => l.replace(/^\||\|$/g, "").split("|").map((c) => c.trim()));
            out.push({ type: "table", head: rows[0], rows: rows.slice(1) });
        } else if (line.startsWith("- ")) {
            out.push({ type: "ul", items: take((l) => l.startsWith("- ")).map((l) => l.slice(2)) });
        } else if (/^\d+\. /.test(line)) {
            const start = parseInt(line, 10);
            out.push({ type: "ol", start, items: take((l) => /^\d+\. /.test(l)).map((l) => l.replace(/^\d+\. /, "")) });
        } else if (line.startsWith("> ")) {
            out.push({ type: "note", text: take((l) => l.startsWith("> ")).map((l) => l.slice(2)).join(" ") });
        } else {
            out.push({ type: "p", text: take((l) => l.trim() && !/^(\||- |\d+\. |> |```)/.test(l)).join(" ") });
        }
    }
    return out;
}

/** Inline spans: **bold**, `code` and [text](link). */
export function inline(text) {
    const parts = [];
    const re = /\*\*(.+?)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)/g;
    let last = 0;
    let m;
    while ((m = re.exec(text))) {
        if (m.index > last) parts.push({ type: "text", text: text.slice(last, m.index) });
        if (m[1] !== undefined) parts.push({ type: "b", text: m[1] });
        else if (m[2] !== undefined) parts.push({ type: "code", text: m[2] });
        else parts.push({ type: "link", text: m[3], to: m[4] });
        last = re.lastIndex;
    }
    if (last < text.length) parts.push({ type: "text", text: text.slice(last) });
    return parts;
}
