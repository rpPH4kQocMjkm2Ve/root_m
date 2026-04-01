#!/usr/bin/env python3
"""Declarative permission management for chezmoi-managed files.

Parses a chezmoiperms file and computes/applies permission actions
for chezmoi-managed paths.

Architecture:
    parse_rules()    — text → list[PermRule]         (pure)
    match_glob()     — pattern × path → bool         (pure)
    compute_actions() — rules × paths → actions      (injectable is_dir)
    apply_actions()  — actions → filesystem mutations (side effects)
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PermRule:
    """Single permission rule from chezmoiperms."""

    pattern: str
    dir_only: bool
    mode: str | None
    owner: str | None
    group: str | None
    line_num: int


@dataclass(frozen=True, slots=True)
class PermAction:
    """Computed permission action for a single target path."""

    path: str
    mode: int | None
    owner: str | None
    group: str | None
    rule: PermRule


class ParseError(Exception):
    """Raised on malformed chezmoiperms content."""

    def __init__(self, line_num: int, message: str) -> None:
        self.line_num = line_num
        super().__init__(f"line {line_num}: {message}")


def parse_rules(content: str) -> list[PermRule]:
    """Parse chezmoiperms content into a list of rules.

    Format per line:
        <glob-pattern>  <mode|->  <owner|->  <group|->

    Pattern ending with ``/`` matches directories only;
    without trailing ``/`` matches files only.
    ``-`` means "don't change this attribute".

    Raises:
        ParseError: on malformed lines.
    """
    rules: list[PermRule] = []

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) != 4:
            raise ParseError(
                line_num,
                f"expected 4 fields (pattern mode owner group), "
                f"got {len(parts)}: {raw_line!r}",
            )

        pattern, mode_s, owner_s, group_s = parts

        mode: str | None = None
        if mode_s != "-":
            if not re.fullmatch(r"0[0-7]{3}", mode_s):
                raise ParseError(
                    line_num,
                    f"invalid mode {mode_s!r}, "
                    f"expected 4-digit octal (e.g. 0644) or '-'",
                )
            mode = mode_s

        owner = owner_s if owner_s != "-" else None
        group = group_s if group_s != "-" else None

        dir_only = pattern.endswith("/")
        if dir_only:
            pattern = pattern.rstrip("/")

        if not pattern:
            raise ParseError(line_num, "empty pattern")

        rules.append(
            PermRule(
                pattern=pattern,
                dir_only=dir_only,
                mode=mode,
                owner=owner,
                group=group,
                line_num=line_num,
            )
        )

    return rules


def _escape_glob_segment(segment: str) -> str:
    """Escape a glob segment (no ``**`` in it) to regex."""
    result = ""
    for ch in segment:
        if ch == "*":
            result += "[^/]*"
        elif ch == "?":
            result += "[^/]"
        else:
            result += re.escape(ch)
    return result


def _compile_glob(pattern: str) -> re.Pattern[str]:
    """Convert a glob pattern with ``**`` support to a compiled regex.

    ``**`` matches zero or more complete path segments:
      - ``a/**/b``   → ``a/b``, ``a/x/b``, ``a/x/y/b``
      - ``a/**``     → ``a``, ``a/x``, ``a/x/y``
      - ``**/*.conf``→ ``f.conf``, ``d/f.conf``

    ``*``  matches anything except ``/``.
    ``?``  matches any single character except ``/``.
    """
    segments = pattern.split("**")

    if len(segments) == 1:
        return re.compile("^" + _escape_glob_segment(segments[0]) + "$")

    escaped = [_escape_glob_segment(s) for s in segments]

    regex = escaped[0]
    for i in range(1, len(escaped)):
        left_slash = segments[i - 1].endswith("/")
        right_slash = segments[i].startswith("/")

        if left_slash and right_slash:
            # a/ ** /b  →  a(/.*)?/b
            # Matches: a/b (zero segments), a/x/b, a/x/y/b
            regex = regex[:-1] + "(/.*)?" + escaped[i]
        elif left_slash and escaped[i] == "":
            # a/ ** (end of pattern)  →  a(/.*)?
            # Matches: a, a/x, a/x/y
            regex = regex[:-1] + "(/.*)?"
        elif right_slash:
            # ** /b (start of pattern)  →  (.*/)?b
            # Matches: b, x/b, x/y/b
            regex = regex + "(.*/)?" + escaped[i][1:]
        else:
            # Bare ** without / boundaries  →  .*
            regex = regex + ".*" + escaped[i]

    return re.compile("^" + regex + "$")


def match_glob(pattern: str, path: str) -> bool:
    """Check if *path* matches *pattern* (with ``**`` support)."""
    return bool(_compile_glob(pattern).match(path))


def compute_actions(
    rules: list[PermRule],
    managed_paths: list[str],
    dest_dir: str,
    *,
    is_dir_func: callable = os.path.isdir,
) -> list[PermAction]:
    """Compute permission actions for *managed_paths*.

    Last matching rule wins.  *is_dir_func* is injectable for unit tests
    that don't touch the real filesystem.
    """
    actions: list[PermAction] = []
    dest_dir = dest_dir.rstrip("/")

    compiled: list[tuple[PermRule, re.Pattern[str]]] = [
        (rule, _compile_glob(rule.pattern)) for rule in rules
    ]

    for target in managed_paths:
        if target == dest_dir:
            continue
        prefix = dest_dir + "/"
        if not target.startswith(prefix):
            continue
        rel = target[len(prefix):]

        is_dir = is_dir_func(target)

        matched_rule: PermRule | None = None
        for rule, regex in compiled:
            if rule.dir_only and not is_dir:
                continue
            if not rule.dir_only and is_dir:
                continue
            if regex.match(rel):
                matched_rule = rule

        if matched_rule is None:
            continue

        mode_int = (
            int(matched_rule.mode, 8) if matched_rule.mode is not None else None
        )

        actions.append(
            PermAction(
                path=target,
                mode=mode_int,
                owner=matched_rule.owner,
                group=matched_rule.group,
                rule=matched_rule,
            )
        )

    return actions


def apply_actions(
    actions: list[PermAction], *, dry_run: bool = False
) -> tuple[bool, list[str]]:
    """Apply permission actions to the filesystem.

    Returns:
        (success, errors) — *success* is True when all actions succeeded,
        *errors* contains human-readable messages for failures.
    """
    errors: list[str] = []

    for action in actions:
        if dry_run:
            mode_s = f"{action.mode:04o}" if action.mode is not None else "-"
            owner_s = action.owner or "-"
            group_s = action.group or "-"
            print(f"{mode_s} {owner_s}:{group_s} {action.path}")
            continue

        if action.mode is not None:
            try:
                os.chmod(action.path, action.mode)
            except OSError as e:
                errors.append(f"chmod {action.mode:04o} {action.path}: {e}")

        if action.owner is not None or action.group is not None:
            try:
                uid = (
                    pwd.getpwnam(action.owner).pw_uid
                    if action.owner is not None
                    else -1
                )
                gid = (
                    grp.getgrnam(action.group).gr_gid
                    if action.group is not None
                    else -1
                )
                os.chown(action.path, uid, gid)
            except (KeyError, OSError) as e:
                errors.append(
                    f"chown {action.owner}:{action.group} {action.path}: {e}"
                )

    return (len(errors) == 0, errors)


# ─── chezmoi helpers (only used by CLI, never by tests) ──────────────────────


def _chezmoi_output(*args: str, timeout: int = 30) -> str:
    result = subprocess.run(
        ["chezmoi", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"chezmoi {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Apply chezmoi permissions")
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Print actions without applying",
    )
    parser.add_argument("--perms-file", type=str, default=None)
    args = parser.parse_args()

    if args.perms_file:
        perms_path = Path(args.perms_file)
    else:
        perms_path = Path(_chezmoi_output("source-path")) / "chezmoiperms"

    if not perms_path.exists():
        return 0

    try:
        rules = parse_rules(perms_path.read_text())
    except ParseError as e:
        print(f"ERROR: {perms_path}: {e}", file=sys.stderr)
        return 1

    if not rules:
        return 0

    managed = _chezmoi_output("managed", "--path-style=absolute").splitlines()
    managed = [p for p in managed if p]
    if not managed:
        print("WARNING: no managed paths found", file=sys.stderr)
        return 0

    dest_dir = _chezmoi_output("target-path")

    actions = compute_actions(rules, managed, dest_dir)
    if not actions:
        return 0

    ok, errors = apply_actions(actions, dry_run=args.dry_run)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
