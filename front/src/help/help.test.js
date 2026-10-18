/**
 * Guards for the in-app help (help/<lang>/<page key>.md): every page has help in both languages,
 * the two languages have the same sections, links go to real pages, and the renderer's pieces.
 */
import { describe, expect, it } from "vitest";
import { ALIASES, blocks, inline, parseHelp, searchHelp } from "./index.js";
import { PAGE_KEYS, pathOfPage } from "../components/sidebarMenu.js";

const RAW = import.meta.glob("./*/*.md", { query: "?raw", import: "default", eager: true });
const LANGS = ["fa", "en"];
const file = (lang, key) => RAW[`./${lang}/${ALIASES[key] || key}.md`];
const files = (lang) => Object.keys(RAW).filter((f) => f.startsWith(`./${lang}/`)).map((f) => f.slice(lang.length + 3, -3));

describe("help content", () => {
    it.each(LANGS)("every page has %s help with a title, a summary and sections", (lang) => {
        const missing = PAGE_KEYS.filter((k) => !file(lang, k));
        expect(missing).toEqual([]);
        for (const key of PAGE_KEYS) {
            const h = parseHelp(file(lang, key));
            expect(h.title, key).not.toBe("");
            expect(h.summary, key).not.toBe("");
            expect(h.sections.length, key).toBeGreaterThan(0);
        }
    });

    it("no help file is left without a page", () => {
        for (const lang of LANGS) expect(files(lang).filter((k) => !PAGE_KEYS.includes(k))).toEqual([]);
    });

    it("Persian and English have the same sections", () => {
        for (const key of files("fa")) {
            const fa = parseHelp(file("fa", key));
            const en = parseHelp(file("en", key));
            expect(en.sections.length, key).toBe(fa.sections.length);
            expect(blocks(en.summary).length, key).toBe(blocks(fa.summary).length);
        }
    });

    it("links go to pages of NGCorion", () => {
        const pages = new Set(PAGE_KEYS.map(pathOfPage));
        for (const f of Object.keys(RAW)) {
            for (const m of RAW[f].matchAll(/\]\(([^)\s]+)\)/g)) {
                expect(pages.has(m[1]), `${f}: ${m[1]}`).toBe(true);
            }
        }
    });

    it("every page key has a URL", () => {
        expect(PAGE_KEYS.filter((k) => !pathOfPage(k))).toEqual([]);
    });
});

describe("help rendering", () => {
    it("splits a file into title, summary and sections", () => {
        const h = parseHelp("# Title\n\nIntro.\n\n## One\n\nBody one.\n\n## Two\n\nBody two.");
        expect(h).toEqual({ title: "Title", summary: "Intro.", sections: [{ title: "One", body: "Body one." }, { title: "Two", body: "Body two." }] });
    });

    it("reads paragraphs, lists, notes and tables", () => {
        const b = blocks("Para line\ncontinued.\n\n- a\n- b\n\n1. x\n2. y\n\n> careful\n\n| H1 | H2 |\n|---|---|\n| c1 | c2 |");
        expect(b.map((x) => x.type)).toEqual(["p", "ul", "ol", "note", "table"]);
        expect(b[0].text).toBe("Para line continued.");
        expect(b[4]).toEqual({ type: "table", head: ["H1", "H2"], rows: [["c1", "c2"]] });
    });

    it("reads fenced code as it is, and blocks indented under a list item", () => {
        const b = blocks("1. Step:\n\n    ```\n    config system global\n     set x 3\n    end\n    ```\n\n    | A | B |\n    |---|---|\n    | 1 | 2 |\n\n2. Next.");
        expect(b.map((x) => x.type)).toEqual(["ol", "pre", "table", "ol"]);
        expect(b[1].text).toBe("config system global\n set x 3\nend");
        expect([b[0].start, b[3].start]).toEqual([1, 2]);
        expect(blocks("```\nconfig system global\n set x 3\nend\n```")[0].text).toBe("config system global\n set x 3\nend");
    });

    it("reads bold, code and links, and nothing else as markup", () => {
        expect(inline("a **b** `c` [d](/e) <i>f</i>")).toEqual([
            { type: "text", text: "a " }, { type: "b", text: "b" }, { type: "text", text: " " },
            { type: "code", text: "c" }, { type: "text", text: " " }, { type: "link", text: "d", to: "/e" },
            { type: "text", text: " <i>f</i>" },
        ]);
    });
});

describe("help search", () => {
    const pages = [
        { key: "audit-trail", title: "Logs", sections: [{ title: "Tabs", body: "Sign-ins and exports" }] },
        { key: "licence", title: "License", sections: [{ title: "Offline activation", body: "request file" }] },
    ];

    it("finds titles before text, only on pages the user may open", () => {
        expect(searchHelp(pages, "offline", ["licence"])).toEqual([{ key: "licence", page: "License", section: "Offline activation" }]);
        expect(searchHelp(pages, "offline", ["audit-trail"])).toEqual([]);
    });

    it("a tab of a page finds its page's help", () => {
        expect(searchHelp(pages, "exports", ["system-logs"])).toEqual([{ key: "audit-trail", page: "Logs", section: "Tabs" }]);
    });

    it("needs two characters", () => {
        expect(searchHelp(pages, "o", ["licence"])).toEqual([]);
    });
});
