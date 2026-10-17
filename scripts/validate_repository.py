#!/usr/bin/env python3
"""Offline checks of tracked documentation and configuration, not a secret audit.

Only tracked regular files are read. Markdown support covers inline links and
reference definitions outside fenced code; it is deliberately not a full parser.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import subprocess
import sys
import unicodedata
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


FORBIDDEN_PARTS = {
    ".codex", ".claude", ".playwright-mcp", ".git", "secrets", "credentials",
    "backups", "uploads", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", ".dart_tool", "build", "dist", "coverage",
}
FORBIDDEN_NAMES = {"auth.json", "credentials.json", "id_rsa", "id_ed25519"}
FORBIDDEN_SUFFIXES = (
    ".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".pyc", ".log",
    ".sqlite", ".sqlite3", ".db", ".sql", ".sql.gz", ".bak", ".backup",
)
SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "openai-key": re.compile(r"\bsk-(?:proj-|svcacct-)[A-Za-z0-9_-]{20,}\b"),
    "literal-credential": re.compile(
        r"(?im)^\s*(?:[\"']?)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
        r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_+/=.-]{12,})"
    ),
}
SAFE_PLACEHOLDERS = {"replace-with-placeholder", "your-api-key-here", "not-a-real-secret"}
INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+[\"'][^\n]*?[\"'])?\s*\)")
REFERENCE_LINK = re.compile(r"^\s{0,3}\[[^\]\n]+\]:\s*(<[^>\n]+>|\S+)", re.MULTILINE)
DECISION = re.compile(r"^- القرار ([0-9]{3})،", re.MULTILINE)
DECISION_REFERENCE = re.compile(r"(?:القرار|بالقرار|قرار)\s+([0-9]{3})(?![0-9])")
MAX_TEXT_BYTES = 5 * 1024 * 1024


def tracked_entries(root: Path) -> list[tuple[str, str]]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--stage", "-z"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    entries = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, _object_id, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise ValueError("unmerged Git index; resolve conflicts first")
        entries.append((mode, name.decode("utf-8", errors="strict")))
    return entries


def prose(text: str) -> str:
    """Blank fenced code while retaining line numbers for useful diagnostics."""
    output = []
    fence = None
    for line in text.splitlines():
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            output.append("")
        else:
            output.append(line if fence is None else "")
    return "\n".join(output)


def heading_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    for match in re.finditer(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", prose(text), re.MULTILINE):
        heading = re.sub(r"<[^>]+>", "", match.group(1)).lower()
        base = "".join(
            char for char in heading
            if char in " -_" or unicodedata.category(char)[0] in "LNM"
        ).replace(" ", "-")
        count = counts.get(base, 0)
        counts[base] = count + 1
        anchors.add(f"{base}-{count}" if count else base)
    return anchors


def validate_repository(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    texts: dict[str, str] = {}
    entries = tracked_entries(root)
    for mode, name in entries:
        if any(ord(char) < 32 or ord(char) == 127 for char in name):
            errors.append("tracked filename contains a control character (name redacted)")
            continue
        path = PurePosixPath(name)
        label = name
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            errors.append(f"{label}: unsafe tracked path")
            continue
        lowered = [part.lower() for part in path.parts]
        basename = lowered[-1]
        if (set(lowered) & FORBIDDEN_PARTS or basename in FORBIDDEN_NAMES
                or basename.endswith(FORBIDDEN_SUFFIXES)
                or (basename.startswith(".env") and basename != ".env.example")):
            errors.append(f"{label}: forbidden tracked file or directory")
            continue
        if mode not in {"100644", "100755"}:
            errors.append(f"{label}: only regular tracked files are allowed (mode {mode})")
            continue
        full = root.joinpath(*path.parts)
        if any(candidate.is_symlink() for candidate in [full, *full.parents] if candidate != root):
            errors.append(f"{label}: symlink file or parent is forbidden")
            continue
        try:
            if full.stat().st_size > MAX_TEXT_BYTES:
                errors.append(f"{label}: exceeds the 5 MiB text-file limit")
                continue
            text = full.read_bytes().decode("utf-8", errors="strict")
        except (OSError, UnicodeError):
            errors.append(f"{label}: missing, unreadable or invalid UTF-8 file")
            continue
        texts[name] = text
        if "\x00" in text or text.startswith("\ufeff") or "\r" in text:
            errors.append(f"{label}: NUL, UTF-8 BOM or non-LF newline")
        if text and not text.endswith("\n"):
            errors.append(f"{label}: missing final newline")
        for line_number, line in enumerate(text.splitlines(), 1):
            if line.rstrip(" \t") != line:
                errors.append(f"{label}:{line_number}: trailing whitespace")
        for rule, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                if rule == "literal-credential" and match.group(1) in SAFE_PLACEHOLDERS:
                    continue
                line_number = text.count("\n", 0, match.start()) + 1
                errors.append(f"{label}:{line_number}: possible secret ({rule}; value redacted)")
                break

    for name, text in texts.items():
        if not name.endswith(".md"):
            continue
        markdown = prose(text)
        for pattern in (INLINE_LINK, REFERENCE_LINK):
            for match in pattern.finditer(markdown):
                target = match.group(1).strip("<>")
                line_number = markdown.count("\n", 0, match.start()) + 1
                label = f"{name}:{line_number}"
                try:
                    parsed = urlsplit(target)
                except ValueError:
                    errors.append(f"{label}: malformed Markdown link (target redacted)")
                    continue
                if parsed.scheme in {"https", "http", "mailto", "tel"}:
                    continue  # Network destinations are deliberately not requested.
                decoded = unquote(parsed.path)
                if parsed.scheme or parsed.netloc or decoded.startswith("/") or "\\" in decoded:
                    errors.append(f"{label}: unsupported or absolute local link (target redacted)")
                    continue
                normalized = posixpath.normpath(posixpath.join(posixpath.dirname(name), decoded)) if decoded else name
                if normalized == ".." or normalized.startswith("../") or any(ord(c) < 32 for c in decoded):
                    errors.append(f"{label}: local link escapes repository or contains controls")
                    continue
                if normalized not in texts:
                    errors.append(f"{label}: local link target is not a validated tracked file")
                    continue
                if parsed.fragment and normalized.endswith(".md"):
                    if unquote(parsed.fragment) not in heading_anchors(texts[normalized]):
                        errors.append(f"{label}: local Markdown heading anchor does not exist")

    plan = texts.get("PROJECT_PLAN.md")
    if plan is None:
        errors.append("PROJECT_PLAN.md: required tracked decision register is missing")
    else:
        decisions = [int(value) for value in DECISION.findall(plan)]
        if not decisions or len(decisions) < 81 or decisions != list(range(1, len(decisions) + 1)):
            errors.append("PROJECT_PLAN.md: decisions must be unique, ordered and contiguous from 001 through at least 081")
        known = set(decisions)
        for name, text in texts.items():
            if name.endswith(".md"):
                for match in DECISION_REFERENCE.finditer(prose(text)):
                    if int(match.group(1)) not in known:
                        line_number = text.count("\n", 0, match.start()) + 1
                        errors.append(f"{name}:{line_number}: reference to undefined decision")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        errors = validate_repository(args.root)
    except (OSError, ValueError, subprocess.CalledProcessError):
        print("Repository validation failed: cannot read a clean, UTF-8 Git index.", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"Repository validation failed: {len(errors)} issue(s).", file=sys.stderr)
        return 1
    print("Repository validation passed for tracked files. This is not security approval or a comprehensive secret scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
