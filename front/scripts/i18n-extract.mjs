// Collects every t("...") / tr("...") / tx("...") / _t("...") key in src and
// syncs src/i18n/locales/fa/<area>.json: new keys are added empty, unused keys
// removed, translations kept. `--check` only reports what is missing.
//   npm run i18n:extract      npm run i18n:check
import fs from "node:fs";
import path from "node:path";
import { parse } from "@babel/parser";
import traverseMod from "@babel/traverse";
const traverse = traverseMod.default?.default || traverseMod.default || traverseMod;

const SRC = path.resolve("src");
const FA = path.join(SRC, "i18n/locales/fa");
const CHECK = process.argv.includes("--check");
const CALLS = new Set(["t", "tr", "tx", "_t", "msg"]);

function areaOf(file) {
    const rel = path.relative(SRC, file).split(path.sep);
    if (rel[0] === "components" && rel.length > 2) return rel[1].toLowerCase();
    if (rel[0] === "store") return "store";
    if (rel[0] === "i18n") return "backend";
    return "common";
}

const keys = new Map(); // key -> area (first seen)
const files = [];
(function walk(d) {
    for (const f of fs.readdirSync(d)) {
        const p = path.join(d, f);
        if (fs.statSync(p).isDirectory()) { if (f !== "locales") walk(p); }
        else if (/\.(jsx?)$/.test(f) && !/\.test\./.test(f)) files.push(p);
    }
})(SRC);
for (const file of files.sort()) {
    const ast = parse(fs.readFileSync(file, "utf8"), { sourceType: "module", plugins: ["jsx"] });
    traverse(ast, {
        CallExpression(p) {
            const c = p.node.callee;
            if (c.type !== "Identifier" || !CALLS.has(c.name)) return;
            const a = p.node.arguments[0];
            if (a && a.type === "StringLiteral" && !keys.has(a.value)) keys.set(a.value, areaOf(file));
        },
    });
}
// Persian has no singular/plural difference after a number, so count keys need one entry.
const existing = {};
if (fs.existsSync(FA)) for (const f of fs.readdirSync(FA)) Object.assign(existing, JSON.parse(fs.readFileSync(path.join(FA, f), "utf8")));
const byArea = {};
let missing = 0;
for (const [k, area] of keys) {
    (byArea[area] ||= {})[k] = existing[k] ?? "";
    if (!existing[k]) missing++;
}
if (CHECK) {
    console.log(`${keys.size} keys, ${missing} without a Persian translation`);
    if (missing && process.argv.includes("--list")) for (const [k] of keys) if (!existing[k]) console.log("  " + k);
    process.exit(missing ? 1 : 0);
}
fs.mkdirSync(FA, { recursive: true });
for (const f of fs.readdirSync(FA)) fs.unlinkSync(path.join(FA, f));
for (const [area, entries] of Object.entries(byArea)) {
    const sorted = Object.fromEntries(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b)));
    fs.writeFileSync(path.join(FA, `${area}.json`), JSON.stringify(sorted, null, 2) + "\n");
}
console.log(`${keys.size} keys in ${Object.keys(byArea).length} files, ${missing} to translate`);
