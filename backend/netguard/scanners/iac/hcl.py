"""A small HCL (Terraform) parser for security checks.

It understands the conventional ``terraform fmt`` layout: blocks opened with ``type "a" "b" {``
on one line, one attribute per line, multi-line lists/maps/functions (bracket balanced) and
heredocs. It does not evaluate expressions, variables or modules: values are kept as source
text, which is what the checks need. Anything it cannot parse is skipped, never guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_BLOCK_OPEN = re.compile(r'^\s*([A-Za-z_][\w-]*)((?:\s+(?:"[^"]*"|[\w-]+))*)\s*\{\s*$')
_ATTR = re.compile(r"^\s*([A-Za-z_][\w.-]*)\s*=\s*(.*)$")
_HEREDOC = re.compile(r"<<-?\s*([A-Za-z_][\w]*)\s*$")


@dataclass
class Attr:
    value: str
    line: int


@dataclass
class Block:
    kind: str
    labels: list[str]
    line: int
    attrs: dict[str, Attr] = field(default_factory=dict)
    children: list[Block] = field(default_factory=list)

    @property
    def type(self) -> str:
        return self.labels[0] if self.labels else ""

    @property
    def name(self) -> str:
        return self.labels[1] if len(self.labels) > 1 else ""

    def get(self, key: str) -> str | None:
        a = self.attrs.get(key)
        return a.value if a else None

    def blocks(self, kind: str) -> list[Block]:
        return [c for c in self.children if c.kind == kind]


def _strip_comment(line: str) -> str:
    out, in_str, i = [], False, 0
    while i < len(line):
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        if not in_str and (c == "#" or line.startswith("//", i)):
            break
        out.append(c)
        i += 1
    return "".join(out).rstrip()


def _depth_delta(text: str) -> int:
    depth, in_str = 0, False
    for i, c in enumerate(text):
        if c == '"' and (i == 0 or text[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str:
            depth += (c in "{[(") - (c in "}])")
    return depth


def unquote(value: str | None) -> str:
    if value is None:
        return ""
    v = value.strip()
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v


def parse(text: str) -> list[Block]:
    """Parse ``text`` into top-level blocks (resource, data, variable, ...)."""
    lines = text.splitlines()
    root = Block("root", [], 0)
    stack: list[Block] = [root]
    i = 0
    in_block_comment = False
    while i < len(lines):
        raw = lines[i]
        n = i + 1
        i += 1
        if in_block_comment:
            in_block_comment = "*/" not in raw
            continue
        if raw.strip().startswith("/*") and "*/" not in raw:
            in_block_comment = True
            continue
        line = _strip_comment(raw)
        if not line.strip():
            continue
        if line.strip() == "}":
            if len(stack) > 1:
                stack.pop()
            continue
        m = _BLOCK_OPEN.match(line)
        if m:
            labels = re.findall(r'"([^"]*)"|([\w-]+)', m.group(2))
            block = Block(m.group(1), [a or b for a, b in labels], n)
            stack[-1].children.append(block)
            stack.append(block)
            continue
        a = _ATTR.match(line)
        if not a:
            continue
        key, value = a.group(1), a.group(2).strip()
        hd = _HEREDOC.search(value)
        if hd:  # heredoc: capture until the terminator line
            marker, body = hd.group(1), []
            while i < len(lines) and lines[i].strip() != marker:
                body.append(lines[i])
                i += 1
            i += 1
            value = "\n".join(body)
        else:
            depth = _depth_delta(value)
            while depth > 0 and i < len(lines):
                nxt = _strip_comment(lines[i])
                i += 1
                value += "\n" + nxt.strip()
                depth += _depth_delta(nxt)
        stack[-1].attrs[key] = Attr(value, n)
    return root.children
