"""
nginx configuration as nginx itself sees it: the output of `nginx -T` (every
file nginx read, each after a "# configuration file PATH:" line) parsed into
one tree, with `include` directives replaced by the directives of the files
they name - so a server block in sites-enabled/ sits under `http` as it does
at run time. Every directive keeps its file and line numbers, which the
hardening edits use.

Inheritance follows nginx: a directive set at one level applies below it
unless a lower level sets it; for array directives (add_header,
proxy_set_header, proxy_hide_header, ...) a level that sets any of them
replaces everything inherited.
"""

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

FILE_MARKER = re.compile(r"^# configuration file (.+):$")
BLOCK_CONTEXTS = ("http", "server", "location", "if", "limit_except")


class ParseError(ValueError):
    pass


@dataclass(eq=False)
class Directive:
    name: str
    args: List[str]
    file: str
    line: int                       # line of the directive's name
    end_line: int                   # line of its ";" or "{"
    children: Optional[List["Directive"]] = None   # None: a simple directive
    close_line: Optional[int] = None               # line of the block's "}"
    parent: Optional["Directive"] = field(default=None, repr=False)

    @property
    def is_block(self) -> bool:
        return self.children is not None

    def ancestors(self) -> Iterator["Directive"]:
        p = self.parent
        while p is not None:
            yield p
            p = p.parent

    def context(self) -> str:
        """'main', 'http', 'server', 'location', ... - where this directive sits."""
        return self.parent.name if self.parent is not None and self.parent.name != "#root" else "main"

    def under(self, name: str) -> bool:
        return any(a.name == name for a in self.ancestors())

    def text(self) -> str:
        return " ".join([self.name] + self.args)

    def walk(self) -> Iterator["Directive"]:
        for c in self.children or []:
            yield c
            yield from c.walk()

    def direct(self, name: str) -> List["Directive"]:
        return [c for c in self.children or [] if c.name == name]


# ── tokenizer ────────────────────────────────────────────────────────────

def tokenize(text: str) -> Iterator[Tuple[str, int, bool]]:
    """(token, line, quoted). Separators "{", "}" and ";" are tokens."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            yield c, line, False
            i += 1
        elif c in "\"'":
            start_line, quote, i, buf = line, c, i + 1, []
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i:i + 2])
                    i += 2
                    continue
                if text[i] == "\n":
                    line += 1
                buf.append(text[i])
                i += 1
            if i >= n:
                raise ParseError(f"unterminated quote starting on line {start_line}")
            i += 1
            yield "".join(buf), start_line, True
        else:
            start, start_line = i, line
            while i < n and text[i] not in " \t\r\n;{}\"'":
                if text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                    j = text.find("}", i)
                    i = j + 1 if j != -1 else n
                    continue
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            yield text[start:i], start_line, False


def _skip_raw_block(text_tokens, line):
    """Skip a *_by_lua_block body: count braces until the block closes."""
    depth = 1
    for tok, ln, quoted in text_tokens:
        if quoted:
            continue
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
            if depth == 0:
                return ln
    raise ParseError(f"unterminated block starting on line {line}")


def parse_file(text: str, path: str) -> List[Directive]:
    tokens = tokenize(text)
    root: List[Directive] = []
    stack: List[Tuple[Optional[Directive], List[Directive]]] = [(None, root)]
    words: List[Tuple[str, int]] = []
    for tok, ln, quoted in tokens:
        if not quoted and tok == ";":
            if not words:
                continue
            parent, sink = stack[-1]
            sink.append(Directive(words[0][0], [w for w, _ in words[1:]], path, words[0][1], ln, parent=parent))
            words = []
        elif not quoted and tok == "{":
            if not words:
                raise ParseError(f"{path}:{ln}: block without a name")
            parent, sink = stack[-1]
            d = Directive(words[0][0], [w for w, _ in words[1:]], path, words[0][1], ln, children=[], parent=parent)
            sink.append(d)
            words = []
            if d.name.endswith("_by_lua_block"):
                d.close_line = _skip_raw_block(tokens, ln)
                continue
            stack.append((d, d.children))
        elif not quoted and tok == "}":
            if words:
                raise ParseError(f"{path}:{ln}: directive without ';'")
            if len(stack) == 1:
                raise ParseError(f"{path}:{ln}: unexpected '}}'")
            block, _ = stack.pop()
            block.close_line = ln
        else:
            words.append((tok, ln))
    if words or len(stack) != 1:
        raise ParseError(f"{path}: unexpected end of file")
    return root


# ── nginx -T output ──────────────────────────────────────────────────────

def split_dump(text: str) -> Dict[str, str]:
    """{path: content} in the order nginx read the files."""
    files: Dict[str, List[str]] = {}
    cur = None
    for line in text.splitlines():
        m = FILE_MARKER.match(line)
        if m:
            cur = m.group(1)
            files.setdefault(cur, [])
        elif cur is not None:
            files[cur].append(line)
    return {p: "\n".join(lines) for p, lines in files.items()}


class Config:
    def __init__(self, dump: str):
        self.files = split_dump(dump)
        if not self.files:
            raise ParseError("no configuration in the nginx -T output")
        self.main_file = next(iter(self.files))
        self.prefix = os.path.dirname(self.main_file)
        self.root = Directive("#root", [], self.main_file, 0, 0, children=[])
        self.root.children = self._expand(parse_file(self.files[self.main_file], self.main_file), self.root, 0)

    def _include(self, pattern: str) -> List[str]:
        if not os.path.isabs(pattern):
            pattern = os.path.join(self.prefix, pattern)
        if not any(ch in pattern for ch in "*?["):
            return [pattern] if pattern in self.files else []
        return sorted(p for p in self.files if fnmatch.fnmatchcase(p, pattern))

    def _expand(self, nodes: List[Directive], parent: Directive, depth: int) -> List[Directive]:
        if depth > 20:
            raise ParseError("include nesting too deep")
        out: List[Directive] = []
        for d in nodes:
            d.parent = parent
            if d.name == "include" and d.args and not d.is_block:
                for path in self._include(d.args[0]):
                    out += self._expand(parse_file(self.files[path], path), parent, depth + 1)
                continue
            if d.is_block:
                d.children = self._expand(d.children, d, depth)
            out.append(d)
        return out

    # ── navigation ──
    def all(self, name: Optional[str] = None) -> List[Directive]:
        return [d for d in self.root.walk() if name is None or d.name == name]

    def main(self, name: str) -> List[Directive]:
        return self.root.direct(name)

    def http(self) -> Optional[Directive]:
        blocks = self.root.direct("http")
        return blocks[0] if blocks else None

    def servers(self) -> List[Directive]:
        h = self.http()
        return h.direct("server") if h else []

    @staticmethod
    def locations(block: Directive) -> List[Directive]:
        return [d for d in block.walk() if d.name == "location"]

    def main_value(self, name: str, default: Optional[str] = None) -> Optional[str]:
        found = self.main(name)
        return " ".join(found[-1].args) if found else default


def effective(block: Directive, name: str) -> List[Directive]:
    """The directives `name` in force in `block`: its own, or the nearest
    enclosing level's (nginx inheritance)."""
    node: Optional[Directive] = block
    while node is not None:
        own = node.direct(name)
        if own:
            return own
        node = node.parent
    return []


def effective_value(block: Directive, name: str, default: Optional[str] = None) -> Optional[str]:
    found = effective(block, name)
    return " ".join(found[-1].args) if found else default


def server_names(server: Directive) -> str:
    names = [a for d in server.direct("server_name") for a in d.args]
    return " ".join(names) if names else "(no server_name)"


def listens(server: Directive) -> List[Tuple[str, List[str]]]:
    """(address:port, parameters) for each listen of a server."""
    out = []
    for d in server.direct("listen"):
        if not d.args:
            continue
        addr = d.args[0]
        if addr.startswith("unix:"):
            key = addr
        elif addr.startswith("["):
            key = addr if "]:" in addr else addr + ":80"
        elif ":" in addr:
            host, port = addr.rsplit(":", 1)
            key = f"{'*' if host in ('*', '0.0.0.0') else host}:{port}"
        elif addr.isdigit():
            key = f"*:{addr}"
        else:
            key = f"{addr}:80"
        out.append((key, d.args[1:]))
    if not out:
        out.append(("*:80", []))
    return out


def is_ssl(server: Directive) -> bool:
    if any("ssl" in params or "quic" in params for _k, params in listens(server)):
        return True
    return any(d.args[:1] == ["on"] for d in server.direct("ssl"))


def server_label(server: Directive) -> str:
    ports = ",".join(sorted({k.rsplit(":", 1)[-1] for k, _p in listens(server)}))
    return f"{server_names(server).split()[0]}:{ports}"
