// Lists user-visible English text in src that is not yet translated.
import fs from "node:fs";
import path from "node:path";
import { parse } from "@babel/parser";
import traverseMod from "@babel/traverse";
const traverse = traverseMod.default?.default || traverseMod.default || traverseMod;

const ROOT = path.resolve(process.argv[2] || "src");
const UI_ATTRS = new Set(["placeholder", "title", "aria-label", "alt", "label", "aria-description", "subtitle", "description", "emptyText", "confirmText", "cancelText", "message", "text", "hint", "tooltip", "header"]);
const files = [];
(function walk(d) {
  for (const f of fs.readdirSync(d)) {
    const p = path.join(d, f);
    if (fs.statSync(p).isDirectory()) { if (f !== "i18n" && f !== "test") walk(p); }
    else if (/\.(jsx?|tsx?)$/.test(f) && !/\.test\./.test(f)) files.push(p);
  }
})(ROOT);

const out = [];
for (const file of files) {
  const src = fs.readFileSync(file, "utf8");
  let ast;
  try { ast = parse(src, { sourceType: "module", plugins: ["jsx"] }); } catch (e) { console.error("PARSE", file, e.message); continue; }
  const add = (kind, node, text) => out.push({ file: path.relative(ROOT, file), line: node.loc.start.line, kind, text });
  traverse(ast, {
    JSXText(p) { const t = p.node.value.replace(/\s+/g, " ").trim(); if (/[A-Za-z]{2,}/.test(t)) add("jsx", p.node, t); },
    JSXAttribute(p) {
      const v = p.node.value; const name = p.node.name.name;
      if (v && v.type === "StringLiteral" && UI_ATTRS.has(name) && /[A-Za-z]{2,}/.test(v.value)) add("attr:" + name, v, v.value);
    },
    StringLiteral(p) {
      const call = p.findParent((x) => x.isCallExpression());
      if (call && call.node.callee.type === "MemberExpression" && call.node.callee.object.name === "console") return;
      if (p.parent.type === "BinaryExpression" && ["===", "!==", "==", "!="].includes(p.parent.operator)) return;
      if (p.parent.type === "SwitchCase") return;
      if (p.parent.type === "JSXAttribute" || p.parent.type === "ImportDeclaration" || p.parent.type === "ExportNamedDeclaration") return;
      if (p.parentPath.isCallExpression() && ["t", "tr", "_t", "require", "uiLocale"].includes(p.parent.callee.name)) return;
      if (p.parentPath.isObjectProperty() && p.parent.key === p.node) return;
      const v = p.node.value;
      if (/^[A-Z][a-z]+.*\s/.test(v) || /^[A-Z][a-z]{2,}$/.test(v) && !/^[A-Z][a-z]+[A-Z]/.test(v)) add("str", p.node, v);
    },
    TemplateLiteral(p) {
      const call = p.findParent((x) => x.isCallExpression());
      if (call && call.node.callee.type === "MemberExpression" && call.node.callee.object.name === "console") return;
      if (p.parent.type === "JSXExpressionContainer" && p.parentPath.parent.type === "JSXAttribute" && ["className", "style", "key", "id", "to", "href"].includes(p.parentPath.parent.name.name)) return;
      if (p.parent.type === "TaggedTemplateExpression") return;
      const raw = p.node.quasis.map((q) => q.value.cooked).join("{}");
      if (/[A-Za-z]{3,} [A-Za-z]{2,}/.test(raw) && !/^[\s{}/.:#?=&-]*$/.test(raw) && !/^(\/|https?:)/.test(raw)) add("tpl", p.node, raw);
    },
  });
}
const byKind = {};
for (const o of out) byKind[o.kind.split(":")[0]] = (byKind[o.kind.split(":")[0]] || 0) + 1;
if (process.argv.includes("--list")) for (const o of out) console.log(`${o.file}:${o.line}\t${o.kind}\t${o.text}`);
console.error("files", files.length, "items", out.length, JSON.stringify(byKind));
const perFile = {};
for (const o of out) perFile[o.file] = (perFile[o.file] || 0) + 1;
if (process.argv.includes("--files")) Object.entries(perFile).sort((a, b) => b[1] - a[1]).forEach(([f, n]) => console.log(n, f));
