"""
Function spans for Juliet-style Java / C / C++ files, without a compiler.

Juliet puts the vulnerable path (bad, badSink, badSource, CWE..._bad) and its
fixed twins (goodG2B, goodB2G, good1, ...Sink) in the SAME file, so scoring has
to know which function a finding's line sits in. Some variants (the _81 family)
put each path in its own class file (..._81_bad.java, ..._81_goodG2B.java) with a
neutral method name, so the file name is checked too.

The parser strips comments and literals, tracks braces, and treats a block as a
function when the text before its "{" looks like a signature. Only outermost
functions are recorded; lambdas and anonymous classes stay inside their parent.
"""
from __future__ import annotations
import re
from functools import lru_cache
from pathlib import Path

CONTROL = {"if", "for", "while", "switch", "catch", "synchronized", "return",
           "new", "else", "do", "try", "finally", "sizeof", "foreach", "using"}
SIG = re.compile(r"([A-Za-z_]\w*)\s*\((?:[^()]|\([^()]*\))*\)\s*(?:const\s*)?"
                 r"(?:throws\s+[\w.,\s]+)?$")


def _strip(src: str) -> str:
    """Blank out comments and string/char literals, keeping newlines and offsets."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(c + " " * max(0, j - i - 2) + (c if j - i >= 2 else ""))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def function_spans(src: str) -> list[tuple[str, int, int]]:
    """[(name, start_line, end_line)] for outermost functions, 1-based inclusive."""
    text = _strip(src)
    spans = []
    depth, boundary = 0, 0
    open_fn: tuple[str, int, int] | None = None   # (name, start_line, depth)
    for i, c in enumerate(text):
        if c in ";":
            boundary = i + 1
        elif c == "{":
            raw = text[boundary:i]
            header = raw.strip()
            if open_fn is None:
                m = SIG.search(header)
                if m and m.group(1) not in CONTROL and not re.search(
                        r"\b(class|interface|enum|struct|namespace)\b", header):
                    lead = len(raw) - len(raw.lstrip())
                    name_pos = boundary + lead + m.start(1)
                    open_fn = (m.group(1), text.count("\n", 0, name_pos) + 1, depth)
            depth += 1
            boundary = i + 1
        elif c == "}":
            depth -= 1
            boundary = i + 1
            if open_fn is not None and depth == open_fn[2]:
                spans.append((open_fn[0], open_fn[1], text.count("\n", 0, i) + 1))
                open_fn = None
    return spans


def region_of(name: str | None, file_stem: str) -> str:
    """'bad', 'good', or 'other' for a function name in a Juliet file."""
    for label in (name or "", file_stem):
        n = label.lower()
        # check the suffix-style names first: ..._81_goodG2B, ..._bad
        if re.search(r"(^|_)bad(sink|source)?\w*$", n) or n.startswith("bad"):
            return "bad"
        if re.search(r"(^|_)good\w*$", n) or n.startswith("good"):
            return "good"
    return "other"


@lru_cache(maxsize=4096)
def _spans_for(path: str, mtime: float) -> tuple[tuple[str, int, int], ...]:
    try:
        return tuple(function_spans(Path(path).read_text(errors="replace")))
    except OSError:
        return ()


def locate(path: Path, line: int) -> tuple[str | None, str]:
    """(function_name, region) for a line in a file."""
    try:
        spans = _spans_for(str(path), path.stat().st_mtime)
    except OSError:
        return None, "other"
    for name, s, e in spans:
        if s <= line <= e:
            return name, region_of(name, path.stem)
    # outside any function: only the file name can say anything
    return None, region_of(None, path.stem) if re.search(r"_(bad|good\w*)$", path.stem) else "other"
