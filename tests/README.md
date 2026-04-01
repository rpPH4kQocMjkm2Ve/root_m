# Tests

## Overview

| File | Language | Framework | What it tests |
|------|----------|-----------|---------------|
| `test_apply_perms.py` | Python | pytest | `apply_perms.py` — rule parsing (`parse_rules`), glob matching (`match_glob`) with `**`/`*`/`?`/literal/escaping, action computation (`compute_actions`) with dir/file filtering, last-match-wins semantics, dest_dir handling, skip markers; filesystem integration (`apply_actions`) for chmod, chown, dry-run, partial failure; full pipeline end-to-end with real directory trees, idempotency verification; PAM safety regression tests |

## Running

```bash
# All tests (requires root for filesystem integration tests)
sudo python -m pytest tests/test_apply_perms.py -v

# Only pure unit tests (no root required)
python -m pytest tests/test_apply_perms.py -v -k "not root_check"

# Specific test class
python -m pytest tests/test_apply_perms.py -v -k "TestParseRules"
python -m pytest tests/test_apply_perms.py -v -k "TestMatchGlob"
python -m pytest tests/test_apply_perms.py -v -k "TestComputeActions"
python -m pytest tests/test_apply_perms.py -v -k "TestApplyActionsChmod"
python -m pytest tests/test_apply_perms.py -v -k "TestFullPipeline"
python -m pytest tests/test_apply_perms.py -v -k "TestPamSafety"
```

## How they work

### Architecture under test

`apply_perms.py` follows a four-stage pipeline:

```
parse_rules()    — text → list[PermRule]         (pure)
match_glob()     — pattern × path → bool         (pure)
compute_actions() — rules × paths → actions      (injectable is_dir)
apply_actions()  — actions → filesystem mutations (side effects)
```

Tests mirror this pipeline, progressing from pure unit tests to full filesystem integration.

### Pure unit tests (no root required)

**`TestParseRules`** — validates the chezmoiperms parser: empty/comment/blank input, single file and directory rules, skip markers (`-`), partial skips, rule ordering with correct `line_num` tracking, trailing slash handling for `dir_only` detection, and error rejection for invalid modes (non-octal, wrong digit count, digits ≥ 8), wrong field count, and empty patterns after slash stripping.

**`TestMatchGlob`** — exercises the custom glob-to-regex compiler: `**` (globstar) matching nested paths, direct children, zero/one/many intermediate components, pattern-start and pattern-end positions; `*` matching single path segments without crossing `/`; `?` matching exactly one character; exact literal matches; regex special character escaping (`.`, `[`, `]`, `+`, `(`, `)` treated as literals); and edge cases (empty pattern vs empty/non-empty path).

**`TestComputeActions`** — tests action computation with an injectable `is_dir_func` to avoid filesystem access: empty rules/paths produce no actions, directory-only rules skip files and vice versa, last-match-wins semantics, skip markers propagate `None` mode/owner/group, `dest_dir` trailing slash normalization, non-root dest_dir prefix stripping, paths outside dest_dir are skipped, dest_dir itself is skipped, specific patterns override globs, duplicate rules resolve to last, deep nesting matches, mixed file/directory trees, and action objects carry a reference to the matched `PermRule`.

### Filesystem integration tests (require root)

These test classes use the `root_check` fixture, which calls `pytest.skip("requires root")` when `euid != 0`. All filesystem operations happen inside pytest's `tmp_path`.

**`TestApplyActionsChmod`** — creates real files/directories in `tmp_path`, applies `PermAction` objects, and verifies resulting `stat.S_IMODE`: file chmod, directory chmod, restrictive mode (0600), nonexistent file produces error, and skip-mode (`mode=None`) leaves permissions unchanged.

**`TestApplyActionsChown`** — tests ownership changes: chown to root, chown to a non-root user (discovers `nobody`/`daemon`/`bin` dynamically), group-only change, and error handling for nonexistent user/group names. Helper functions `_get_non_root_user()` and `_get_non_root_group()` probe the system for available accounts, skipping tests if none exist.

**`TestApplyActionsCombined`** — verifies chmod and chown applied together, multiple actions in a single `apply_actions` call, and partial failure (one bad action doesn't prevent others from applying — the good file still gets its permissions).

**`TestApplyActionsDryRun`** — confirms `dry_run=True` prints actions to stdout without modifying the filesystem.

### Full pipeline tests (require root)

**`TestFullPipeline`** — end-to-end tests that build a realistic directory tree (`etc/`, `etc/security/`, `etc/polkit-1/rules.d/`, `etc/systemd/network/`, `efi/loader/`, `root/`) with all permissions set to 0777, parse a multi-section chezmoiperms ruleset, compute actions, apply them, and assert exact permission values for every path: base directories (0755), sensitive directories (0700), regular config files (0644), security files (0600), polkit rules (0640), executables (0755), and root home files (0600). Includes an idempotency test (applying twice produces identical `stat` results) and an ownership pipeline test that chains parse → compute → apply with real `chown` to a non-root user/group.

### PAM safety regression tests (no root required)

**`TestPamSafety`** — regression tests for the 2026-04-01 incident where `etc/security/** 0600` broke PAM authentication system-wide. PAM modules (`pam_faillock`, `pam_unix`, etc.) run inside the calling process — not as root. When `hyprlock` (uid=1000) or `polkit-agent-helper` invokes PAM, the module must be able to read `/etc/security/faillock.conf`. With mode `0600 root:root`, others-read is absent and `pam_authenticate` fails completely.

Tests verify:
- `0600` removes the others-read bit (reproduces the bug)
- `0644` preserves the others-read bit (confirms the fix)
- Last-match-wins semantics can silently override a safe default with an unsafe specific rule
- **Production guard**: parametrized test reads the actual `chezmoiperms` file from the repo and validates that every known PAM config (`faillock.conf`, `access.conf`, `limits.conf`, `pam_env.conf`, etc.) retains world-readable permissions — catches regressions on any future edit

## Test environment

- Pure tests (`TestParseRules`, `TestMatchGlob`, `TestComputeActions`, `TestPamSafety`) run without root and without filesystem access
- Filesystem tests use pytest's `tmp_path` fixture — no system files are touched
- Root is required only for `chmod`/`chown` integration tests; non-root runs skip them automatically via `root_check`
- Non-root user/group discovery is dynamic (`nobody`/`daemon`/`bin`); tests skip gracefully if none are available
- `scripts/apply_perms.py` is imported via `sys.path` manipulation (`sys.path.insert(0, …)`) rather than package installation

## CI

Tests run automatically on push/PR when source, rules, test, or workflow files change (path-filtered). The workflow has two jobs:

- **lint** — `ruff check` and `mypy --strict` against `scripts/apply_perms.py` (Python 3.14)
- **test** — `sudo python -m pytest tests/test_apply_perms.py -v` (runs as root so filesystem integration tests are not skipped)
