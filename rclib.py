"""rclib — shared runtime for RedCell tools.

Gives every tool a consistent, professional shape: argument parsing, an
authorisation gate, structured findings, coloured status output, and JSON
export. Tools import this and implement one `run(ctx)` function, so they all
behave and read the same way instead of being ad-hoc scripts.

Drop this file next to a tool (RedCell clones it alongside), or install it on
PYTHONPATH.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable

_C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[34m",
      "c": "\033[36m", "d": "\033[2m", "x": "\033[0m", "bold": "\033[1m"}

# Windows consoles often use a legacy codepage (cp1252/cp1256) that cannot
# encode box-drawing/ANSI-adjacent glyphs. Force UTF-8 where possible, and fall
# back to ASCII-only output otherwise, so a tool never crashes on its own banner.
_UNICODE_OK = True
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # py3.7+
    except Exception:
        enc = (getattr(_stream, "encoding", "") or "").lower()
        if "utf" not in enc:
            _UNICODE_OK = False

_USE_COLOR = sys.stdout.isatty()


def _c(s, k):
    return f"{_C[k]}{s}{_C['x']}" if _USE_COLOR else s


def _sym(unicode_s, ascii_s):
    return unicode_s if _UNICODE_OK else ascii_s


SEV = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    title: str
    severity: str = "info"
    detail: str = ""
    evidence: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEV:
            self.severity = "info"


@dataclass
class Context:
    args: argparse.Namespace
    tool: str
    target: str
    findings: list = field(default_factory=list)
    data: dict = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    # ---- output helpers ----
    def info(self, msg): print(f"{_c('[*]', 'b')} {msg}")
    def good(self, msg): print(f"{_c('[+]', 'g')} {msg}")
    def warn(self, msg): print(f"{_c('[!]', 'y')} {msg}")
    def err(self, msg): print(f"{_c('[x]', 'r')} {msg}", file=sys.stderr)
    def step(self, msg): print(f"{_c('  ->', 'd')} {msg}")

    def finding(self, title, severity="info", detail="", **evidence):
        f = Finding(title, severity, detail, evidence)
        self.findings.append(f)
        colour = {"critical": "r", "high": "r", "medium": "y", "low": "c", "info": "d"}[f.severity]
        print(f"{_c('[' + f.severity.upper() + ']', colour)} {title}"
              + (f" {_c('— ' + detail, 'd')}" if detail else ""))
        return f

    def summary(self):
        by = {s: sum(1 for f in self.findings if f.severity == s) for s in SEV}
        took = time.time() - self.started
        print()
        print(_c(f"{_sym('──', '--')} {self.tool} complete ", "bold") + _c(f"({took:.1f}s)", "d"))
        line = "   " + "  ".join(f"{by[s]} {s}" for s in SEV if by[s])
        print(line if line.strip() else _c("   no findings", "d"))

    def to_json(self):
        return {
            "tool": self.tool, "target": self.target,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "findings": [{"title": f.title, "severity": f.severity, "detail": f.detail,
                          "evidence": f.evidence} for f in self.findings],
            "data": self.data,
        }


def main(tool: str, description: str, run: Callable[[Context], int],
         extra_args: Callable[[argparse.ArgumentParser], None] | None = None,
         needs_target: bool = True) -> int:
    """Standard entrypoint. `run(ctx)` does the work and returns an exit code."""
    p = argparse.ArgumentParser(prog=tool, description=description)
    if needs_target:
        p.add_argument("target", nargs="?", help="target host, domain, URL, or file")
    else:
        p.add_argument("target", nargs="?", default="", help="optional target")
    p.add_argument("-o", "--output", help="write JSON results to this file")
    p.add_argument("-q", "--quiet", action="store_true", help="only findings")
    p.add_argument("-y", "--yes", action="store_true", help="skip authorisation prompt")
    if extra_args:
        extra_args(p)
    args = p.parse_args()

    if needs_target and not args.target:
        p.error("a target is required")

    if not args.yes:
        try:
            ans = input(f"Authorised to test {args.target or 'this host'}? [y/N] ")
        except EOFError:
            ans = "n"
        if ans.strip().lower() not in ("y", "yes"):
            print("[!] authorisation not confirmed; aborting.")
            return 1

    if not args.quiet:
        top = _sym("┌─", "==")
        bot = _sym("└─", "  ")
        dot = _sym("·", "-")
        print(_c(f"{top} {tool}", "bold") + _c(f" {dot} {description}", "d"))
        if args.target:
            print(_c(f"{bot} target: {args.target}", "d"))
        print()

    ctx = Context(args=args, tool=tool, target=args.target or "")
    try:
        code = run(ctx)
    except KeyboardInterrupt:
        ctx.err("interrupted")
        return 130
    except Exception as e:  # noqa: BLE001 — surface tool errors cleanly
        ctx.err(f"{type(e).__name__}: {e}")
        return 1

    if not args.quiet:
        ctx.summary()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(ctx.to_json(), fh, indent=2)
        ctx.info(f"results written to {args.output}")
    return code if isinstance(code, int) else 0
