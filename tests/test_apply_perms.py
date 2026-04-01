"""Tests for apply_perms.py

These tests run as root (root-chezmoi context), which allows testing
real chmod/chown operations in tmp_path.
"""

import grp
import os
import pwd
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from apply_perms import (
    ParseError,
    PermAction,
    PermRule,
    apply_actions,
    compute_actions,
    match_glob,
    parse_rules,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def root_check():
    """Skip test if not running as root."""
    if os.geteuid() != 0:
        pytest.skip("requires root")


def _resolve_uid(name: str) -> int | None:
    """Return uid for username, or None if user doesn't exist."""
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _resolve_gid(name: str) -> int | None:
    """Return gid for group name, or None if group doesn't exist."""
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def _get_non_root_user() -> tuple[str, int] | None:
    """Find a non-root user (e.g. 'nobody' or 'daemon') for chown tests."""
    for name in ("nobody", "daemon", "bin"):
        uid = _resolve_uid(name)
        if uid is not None and uid != 0:
            return (name, uid)
    return None


def _get_non_root_group() -> tuple[str, int] | None:
    """Find a non-root group for chown tests."""
    for name in ("nobody", "nogroup", "daemon", "bin"):
        gid = _resolve_gid(name)
        if gid is not None and gid != 0:
            return (name, gid)
    return None


# ─── parse_rules() ───────────────────────────────────────────────────────────


class TestParseRules:
    def test_empty(self):
        assert parse_rules("") == []

    def test_comments_only(self):
        assert parse_rules("# comment\n# another\n") == []

    def test_blank_lines(self):
        assert parse_rules("\n\n\n") == []

    def test_single_file_rule(self):
        rules = parse_rules("etc/** 0644 root root\n")
        assert len(rules) == 1
        r = rules[0]
        assert r.pattern == "etc/**"
        assert not r.dir_only
        assert r.mode == "0644"
        assert r.owner == "root"
        assert r.group == "root"
        assert r.line_num == 1

    def test_single_dir_rule(self):
        rules = parse_rules("etc/**/ 0755 root root\n")
        assert len(rules) == 1
        r = rules[0]
        assert r.pattern == "etc/**"
        assert r.dir_only
        assert r.mode == "0755"

    def test_skip_marker(self):
        rules = parse_rules("etc/** - - -\n")
        assert len(rules) == 1
        r = rules[0]
        assert r.mode is None
        assert r.owner is None
        assert r.group is None

    def test_partial_skip(self):
        rules = parse_rules("etc/** 0600 - root\n")
        r = parse_rules("etc/** 0600 - root\n")[0]
        assert r.mode == "0600"
        assert r.owner is None
        assert r.group == "root"

    def test_multiple_rules_ordering(self):
        content = """\
# Base
etc/**/  0755  root  root
etc/**   0644  root  root
# Sensitive
etc/security/**  0600  root  root
"""
        rules = parse_rules(content)
        assert len(rules) == 3
        assert rules[0].dir_only
        assert rules[0].line_num == 2
        assert not rules[1].dir_only
        assert rules[1].line_num == 3
        assert rules[2].mode == "0600"
        assert rules[2].line_num == 5

    def test_invalid_mode_not_octal(self):
        with pytest.raises(ParseError, match="invalid mode"):
            parse_rules("etc/** 9999 root root\n")

    def test_invalid_mode_three_digits(self):
        with pytest.raises(ParseError, match="invalid mode"):
            parse_rules("etc/** 644 root root\n")

    def test_invalid_mode_five_digits(self):
        with pytest.raises(ParseError, match="invalid mode"):
            parse_rules("etc/** 00644 root root\n")

    def test_invalid_mode_has_eight(self):
        with pytest.raises(ParseError, match="invalid mode"):
            parse_rules("etc/** 0889 root root\n")

    def test_too_few_fields(self):
        with pytest.raises(ParseError, match="expected 4 fields"):
            parse_rules("etc/** 0644 root\n")

    def test_too_many_fields(self):
        with pytest.raises(ParseError, match="expected 4 fields"):
            parse_rules("etc/** 0644 root root extra\n")

    def test_empty_pattern_after_slash_strip(self):
        with pytest.raises(ParseError, match="empty pattern"):
            parse_rules("/ 0755 root root\n")

    def test_line_numbers_with_blanks(self):
        content = "\n# comment\n\netc/** 0644 root root\n"
        rules = parse_rules(content)
        assert rules[0].line_num == 4

    def test_trailing_slash_variations(self):
        rules = parse_rules("etc/foo// 0755 root root\n")
        assert rules[0].dir_only
        assert rules[0].pattern == "etc/foo"


# ─── match_glob() ────────────────────────────────────────────────────────────


class TestMatchGlob:
    # ** (globstar)

    def test_double_star_matches_nested(self):
        assert match_glob("etc/**", "etc/foo/bar/baz.conf")

    def test_double_star_matches_direct_child(self):
        assert match_glob("etc/**", "etc/pacman.conf")

    def test_double_star_no_match_outside(self):
        assert not match_glob("etc/**", "usr/lib/foo")

    def test_double_star_no_match_prefix(self):
        assert not match_glob("etc/**", "etcfoo")

    def test_double_star_at_start(self):
        assert match_glob("**/*.conf", "etc/foo/bar.conf")

    def test_double_star_at_start_direct(self):
        assert match_glob("**/*.conf", "bar.conf")

    def test_double_star_middle(self):
        assert match_glob(
            "etc/**/rules.d/**", "etc/polkit-1/rules.d/99-foo.rules"
        )

    def test_double_star_only(self):
        assert match_glob("**", "anything/at/all")

    def test_double_star_only_single(self):
        assert match_glob("**", "file")

    def test_double_star_zero_components(self):
        """etc/**/foo matches etc/foo (zero intermediate components)."""
        assert match_glob("etc/**/foo", "etc/foo")

    def test_double_star_one_component(self):
        assert match_glob("etc/**/foo", "etc/bar/foo")

    def test_double_star_many_components(self):
        assert match_glob("etc/**/foo", "etc/a/b/c/foo")

    # * (single star)

    def test_single_star_matches_filename(self):
        assert match_glob("etc/*", "etc/pacman.conf")

    def test_single_star_no_nested(self):
        assert not match_glob("etc/*", "etc/foo/bar.conf")

    def test_single_star_middle(self):
        assert match_glob("etc/*/conf.d", "etc/fontconfig/conf.d")

    # ?

    def test_question_mark(self):
        assert match_glob("etc/?.conf", "etc/a.conf")

    def test_question_mark_no_multi(self):
        assert not match_glob("etc/?.conf", "etc/ab.conf")

    # Literal

    def test_exact_match(self):
        assert match_glob("etc/pacman.conf", "etc/pacman.conf")

    def test_exact_no_match(self):
        assert not match_glob("etc/pacman.conf", "etc/pacman.conf.bak")

    # Escaping

    def test_regex_special_chars_escaped(self):
        assert match_glob("etc/foo.conf", "etc/foo.conf")
        assert not match_glob("etc/foo.conf", "etc/fooXconf")

    def test_brackets_literal(self):
        assert match_glob("etc/[foo]", "etc/[foo]")
        assert not match_glob("etc/[foo]", "etc/f")

    def test_plus_literal(self):
        assert match_glob("etc/foo+bar", "etc/foo+bar")

    def test_parentheses_literal(self):
        assert match_glob("etc/(foo)", "etc/(foo)")
        assert not match_glob("etc/(foo)", "etc/foo")

    # Edge cases

    def test_empty_pattern_empty_path(self):
        assert match_glob("", "")

    def test_empty_pattern_nonempty_path(self):
        assert not match_glob("", "foo")


# ─── compute_actions() — unit tests with injected is_dir ─────────────────────


def _dir_set(dirs: set[str]):
    """Return an is_dir_func that treats paths in *dirs* as directories."""
    return lambda path: path in dirs


class TestComputeActions:
    def test_empty_rules(self):
        actions = compute_actions(
            [], ["/etc/foo"], "/", is_dir_func=lambda _: False
        )
        assert actions == []

    def test_empty_managed(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(rules, [], "/", is_dir_func=lambda _: False)
        assert actions == []

    def test_single_file_match(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(
            rules,
            ["/etc/pacman.conf"],
            "/",
            is_dir_func=lambda _: False,
        )
        assert len(actions) == 1
        a = actions[0]
        assert a.path == "/etc/pacman.conf"
        assert a.mode == 0o644
        assert a.owner == "root"
        assert a.group == "root"

    def test_dir_rule_skips_files(self):
        rules = parse_rules("etc/**/ 0755 root root\n")
        actions = compute_actions(
            rules,
            ["/etc/pacman.conf"],
            "/",
            is_dir_func=lambda _: False,
        )
        assert actions == []

    def test_dir_rule_matches_dirs(self):
        rules = parse_rules("etc/**/ 0755 root root\n")
        actions = compute_actions(
            rules,
            ["/etc/security"],
            "/",
            is_dir_func=_dir_set({"/etc/security"}),
        )
        assert len(actions) == 1
        assert actions[0].mode == 0o755

    def test_file_rule_skips_dirs(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(
            rules,
            ["/etc/security"],
            "/",
            is_dir_func=_dir_set({"/etc/security"}),
        )
        assert actions == []

    def test_last_match_wins(self):
        content = "etc/** 0644 root root\netc/security/** 0600 root root\n"
        rules = parse_rules(content)
        actions = compute_actions(
            rules,
            ["/etc/security/faillock.conf", "/etc/pacman.conf"],
            "/",
            is_dir_func=lambda _: False,
        )
        by_path = {a.path: a for a in actions}
        assert by_path["/etc/security/faillock.conf"].mode == 0o600
        assert by_path["/etc/pacman.conf"].mode == 0o644

    def test_skip_mode(self):
        rules = parse_rules("etc/** - root root\n")
        actions = compute_actions(
            rules, ["/etc/foo"], "/", is_dir_func=lambda _: False
        )
        assert actions[0].mode is None
        assert actions[0].owner == "root"

    def test_dest_dir_trailing_slashes(self):
        rules = parse_rules("etc/** 0644 root root\n")
        for dest in ("/", "///"):
            actions = compute_actions(
                rules,
                ["/etc/foo"],
                dest,
                is_dir_func=lambda _: False,
            )
            assert len(actions) == 1

    def test_non_root_dest_dir(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(
            rules,
            ["/custom/dest/etc/foo.conf"],
            "/custom/dest",
            is_dir_func=lambda _: False,
        )
        assert len(actions) == 1
        assert actions[0].path == "/custom/dest/etc/foo.conf"

    def test_path_outside_dest_dir_skipped(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(
            rules,
            ["/other/etc/foo"],
            "/dest",
            is_dir_func=lambda _: False,
        )
        assert actions == []

    def test_no_matching_rule(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(
            rules,
            ["/usr/lib/foo"],
            "/",
            is_dir_func=lambda _: False,
        )
        assert actions == []

    def test_mixed_files_and_dirs(self):
        content = "etc/**/ 0755 root root\netc/** 0644 root root\n"
        rules = parse_rules(content)
        dirs = {"/etc", "/etc/security"}
        managed = [
            "/etc",
            "/etc/security",
            "/etc/pacman.conf",
            "/etc/security/faillock.conf",
        ]
        actions = compute_actions(
            rules, managed, "/", is_dir_func=_dir_set(dirs)
        )
        by_path = {a.path: a for a in actions}
        assert by_path["/etc"].mode == 0o755
        assert by_path["/etc/security"].mode == 0o755
        assert by_path["/etc/pacman.conf"].mode == 0o644
        assert by_path["/etc/security/faillock.conf"].mode == 0o644

    def test_action_has_rule_reference(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(
            rules, ["/etc/foo"], "/", is_dir_func=lambda _: False
        )
        assert actions[0].rule is rules[0]

    def test_specific_group(self):
        content = (
            "etc/** 0644 root root\n"
            "etc/polkit-1/rules.d/** 0750 root polkitd\n"
        )
        rules = parse_rules(content)
        actions = compute_actions(
            rules,
            ["/etc/polkit-1/rules.d/99-sing-box.rules"],
            "/",
            is_dir_func=lambda _: False,
        )
        assert actions[0].mode == 0o750
        assert actions[0].group == "polkitd"

    def test_dest_dir_itself_skipped(self):
        rules = parse_rules("** 0644 root root\n")
        actions = compute_actions(
            rules, ["/"], "/", is_dir_func=lambda _: True
        )
        assert actions == []

    def test_specific_file_overrides_glob(self):
        content = "etc/** 0644 root root\netc/pacman.conf 0600 root root\n"
        rules = parse_rules(content)
        actions = compute_actions(
            rules,
            ["/etc/pacman.conf", "/etc/other.conf"],
            "/",
            is_dir_func=lambda _: False,
        )
        by_path = {a.path: a for a in actions}
        assert by_path["/etc/pacman.conf"].mode == 0o600
        assert by_path["/etc/other.conf"].mode == 0o644

    def test_duplicate_rules_last_wins(self):
        content = "etc/** 0644 root root\netc/** 0600 root root\n"
        rules = parse_rules(content)
        actions = compute_actions(
            rules, ["/etc/foo"], "/", is_dir_func=lambda _: False
        )
        assert actions[0].mode == 0o600

    def test_deeply_nested(self):
        rules = parse_rules("etc/** 0644 root root\n")
        actions = compute_actions(
            rules,
            ["/etc/a/b/c/d/e/f/g.conf"],
            "/",
            is_dir_func=lambda _: False,
        )
        assert len(actions) == 1


# ─── Filesystem integration tests (require root) ────────────────────────────


class TestApplyActionsChmod:
    """Test chmod operations with real filesystem."""

    def test_chmod_file(self, tmp_path, root_check):
        f = tmp_path / "test.conf"
        f.write_text("content")
        f.chmod(0o777)

        action = PermAction(
            path=str(f),
            mode=0o644,
            owner=None,
            group=None,
            rule=PermRule("**", False, "0644", None, None, 1),
        )

        ok, errors = apply_actions([action])
        assert ok
        assert errors == []
        assert stat.S_IMODE(f.stat().st_mode) == 0o644

    def test_chmod_directory(self, tmp_path, root_check):
        d = tmp_path / "subdir"
        d.mkdir()
        d.chmod(0o777)

        action = PermAction(
            path=str(d),
            mode=0o755,
            owner=None,
            group=None,
            rule=PermRule("**", True, "0755", None, None, 1),
        )

        ok, errors = apply_actions([action])
        assert ok
        assert stat.S_IMODE(d.stat().st_mode) == 0o755

    def test_chmod_restrictive(self, tmp_path, root_check):
        f = tmp_path / "secret"
        f.write_text("secret")
        f.chmod(0o644)

        action = PermAction(
            path=str(f),
            mode=0o600,
            owner=None,
            group=None,
            rule=PermRule("**", False, "0600", None, None, 1),
        )

        ok, _ = apply_actions([action])
        assert ok
        assert stat.S_IMODE(f.stat().st_mode) == 0o600

    def test_chmod_nonexistent_file(self, tmp_path, root_check):
        action = PermAction(
            path=str(tmp_path / "nonexistent"),
            mode=0o644,
            owner=None,
            group=None,
            rule=PermRule("**", False, "0644", None, None, 1),
        )

        ok, errors = apply_actions([action])
        assert not ok
        assert len(errors) == 1
        assert "chmod" in errors[0]

    def test_skip_mode_no_chmod(self, tmp_path, root_check):
        f = tmp_path / "test"
        f.write_text("")
        f.chmod(0o777)

        action = PermAction(
            path=str(f),
            mode=None,
            owner=None,
            group=None,
            rule=PermRule("**", False, None, None, None, 1),
        )

        ok, errors = apply_actions([action])
        assert ok
        assert stat.S_IMODE(f.stat().st_mode) == 0o777


class TestApplyActionsChown:
    """Test chown operations with real filesystem."""

    def test_chown_to_root(self, tmp_path, root_check):
        f = tmp_path / "test"
        f.write_text("")

        action = PermAction(
            path=str(f),
            mode=None,
            owner="root",
            group="root",
            rule=PermRule("**", False, None, "root", "root", 1),
        )

        ok, errors = apply_actions([action])
        assert ok
        assert errors == []
        st = f.stat()
        assert st.st_uid == 0
        assert st.st_gid == 0

    def test_chown_to_nonroot_user(self, tmp_path, root_check):
        user_info = _get_non_root_user()
        if user_info is None:
            pytest.skip("no non-root user available")

        name, uid = user_info
        f = tmp_path / "test"
        f.write_text("")

        action = PermAction(
            path=str(f),
            mode=None,
            owner=name,
            group=None,
            rule=PermRule("**", False, None, name, None, 1),
        )

        ok, errors = apply_actions([action])
        assert ok
        assert f.stat().st_uid == uid

    def test_chown_group_only(self, tmp_path, root_check):
        group_info = _get_non_root_group()
        if group_info is None:
            pytest.skip("no non-root group available")

        name, gid = group_info
        f = tmp_path / "test"
        f.write_text("")

        action = PermAction(
            path=str(f),
            mode=None,
            owner=None,
            group=name,
            rule=PermRule("**", False, None, None, name, 1),
        )

        ok, errors = apply_actions([action])
        assert ok
        assert f.stat().st_gid == gid

    def test_chown_nonexistent_user(self, tmp_path, root_check):
        f = tmp_path / "test"
        f.write_text("")

        action = PermAction(
            path=str(f),
            mode=None,
            owner="nonexistent_user_xyz_12345",
            group=None,
            rule=PermRule("**", False, None, "nonexistent_user_xyz_12345", None, 1),
        )

        ok, errors = apply_actions([action])
        assert not ok
        assert len(errors) == 1
        assert "chown" in errors[0]

    def test_chown_nonexistent_group(self, tmp_path, root_check):
        f = tmp_path / "test"
        f.write_text("")

        action = PermAction(
            path=str(f),
            mode=None,
            owner=None,
            group="nonexistent_group_xyz_12345",
            rule=PermRule("**", False, None, None, "nonexistent_group_xyz_12345", 1),
        )

        ok, errors = apply_actions([action])
        assert not ok
        assert "chown" in errors[0]


class TestApplyActionsCombined:
    """Test chmod + chown together."""

    def test_chmod_and_chown(self, tmp_path, root_check):
        f = tmp_path / "test"
        f.write_text("")
        f.chmod(0o777)

        action = PermAction(
            path=str(f),
            mode=0o600,
            owner="root",
            group="root",
            rule=PermRule("**", False, "0600", "root", "root", 1),
        )

        ok, errors = apply_actions([action])
        assert ok
        assert errors == []
        st = f.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert st.st_uid == 0
        assert st.st_gid == 0

    def test_multiple_actions(self, tmp_path, root_check):
        f1 = tmp_path / "public"
        f2 = tmp_path / "secret"
        f1.write_text("")
        f2.write_text("")
        f1.chmod(0o777)
        f2.chmod(0o777)

        actions = [
            PermAction(
                path=str(f1),
                mode=0o644,
                owner="root",
                group="root",
                rule=PermRule("**", False, "0644", "root", "root", 1),
            ),
            PermAction(
                path=str(f2),
                mode=0o600,
                owner="root",
                group="root",
                rule=PermRule("**", False, "0600", "root", "root", 2),
            ),
        ]

        ok, errors = apply_actions(actions)
        assert ok
        assert stat.S_IMODE(f1.stat().st_mode) == 0o644
        assert stat.S_IMODE(f2.stat().st_mode) == 0o600

    def test_partial_failure(self, tmp_path, root_check):
        """One bad action doesn't prevent others from applying."""
        good = tmp_path / "good"
        good.write_text("")
        good.chmod(0o777)

        actions = [
            PermAction(
                path=str(tmp_path / "nonexistent"),
                mode=0o644,
                owner=None,
                group=None,
                rule=PermRule("**", False, "0644", None, None, 1),
            ),
            PermAction(
                path=str(good),
                mode=0o600,
                owner=None,
                group=None,
                rule=PermRule("**", False, "0600", None, None, 2),
            ),
        ]

        ok, errors = apply_actions(actions)
        assert not ok
        assert len(errors) == 1
        # Second action still applied
        assert stat.S_IMODE(good.stat().st_mode) == 0o600


class TestApplyActionsDryRun:
    def test_dry_run_no_changes(self, tmp_path, root_check):
        f = tmp_path / "test"
        f.write_text("")
        f.chmod(0o777)

        action = PermAction(
            path=str(f),
            mode=0o644,
            owner="root",
            group="root",
            rule=PermRule("**", False, "0644", "root", "root", 1),
        )

        ok, errors = apply_actions([action], dry_run=True)
        assert ok
        # File unchanged
        assert stat.S_IMODE(f.stat().st_mode) == 0o777


# ─── Full pipeline: parse → compute → apply (with real FS) ──────────────────


class TestFullPipeline:
    """End-to-end tests creating a real directory tree in tmp_path."""

    def _build_tree(self, root: Path) -> list[str]:
        """Create a mock system tree, return list of all paths."""
        paths: list[str] = []

        dirs = [
            "etc",
            "etc/security",
            "etc/polkit-1",
            "etc/polkit-1/rules.d",
            "etc/systemd",
            "etc/systemd/network",
            "efi",
            "efi/loader",
            "root",
        ]
        for d in dirs:
            (root / d).mkdir(parents=True, exist_ok=True)
            paths.append(str(root / d))

        files = [
            "etc/pacman.conf",
            "etc/mkinitcpio.conf",
            "etc/security/faillock.conf",
            "etc/polkit-1/rules.d/99-sing-box.rules",
            "etc/systemd/network/10-wire.network",
            "etc/systemd/coredump.conf",
            "efi/loader/loader.conf",
            "root/.zshrc",
        ]
        for f in files:
            (root / f).parent.mkdir(parents=True, exist_ok=True)
            (root / f).write_text("")
            # Start with permissive permissions
            (root / f).chmod(0o777)
            paths.append(str(root / f))

        # Dirs also start permissive
        for d in dirs:
            (root / d).chmod(0o777)

        return paths

    def test_full_rule_set(self, tmp_path, root_check):
        managed = self._build_tree(tmp_path)
        dest_dir = str(tmp_path)

        content = """\
# Directories
efi/**/                   0755  root  root
etc/**/                   0755  root  root
etc/security/             0700  root  root
root/**/                  0700  root  root

# Files — base
efi/**                    0644  root  root
etc/**                    0644  root  root
root/**                   0600  root  root

# Executables
efi/loader/loader.conf    0755  root  root

# Sensitive
etc/security/**           0600  root  root
etc/polkit-1/rules.d/**   0640  root  root
"""
        rules = parse_rules(content)
        actions = compute_actions(rules, managed, dest_dir)
        ok, errors = apply_actions(actions)

        assert ok, f"apply_actions failed: {errors}"

        def mode(rel: str) -> int:
            return stat.S_IMODE((tmp_path / rel).stat().st_mode)

        # Directories
        assert mode("etc") == 0o755
        assert mode("etc/security") == 0o700
        assert mode("etc/polkit-1") == 0o755
        assert mode("etc/polkit-1/rules.d") == 0o755
        assert mode("etc/systemd") == 0o755
        assert mode("etc/systemd/network") == 0o755
        assert mode("root") == 0o700
        assert mode("efi") == 0o755
        assert mode("efi/loader") == 0o755

        # Regular files
        assert mode("etc/pacman.conf") == 0o644
        assert mode("etc/mkinitcpio.conf") == 0o644
        assert mode("etc/systemd/coredump.conf") == 0o644
        assert mode("etc/systemd/network/10-wire.network") == 0o644

        # Sensitive
        assert mode("etc/security/faillock.conf") == 0o600

        # Polkit
        assert mode("etc/polkit-1/rules.d/99-sing-box.rules") == 0o640

        # Executable
        assert mode("efi/loader/loader.conf") == 0o755

        # Root home
        assert mode("root/.zshrc") == 0o600

    def test_idempotent(self, tmp_path, root_check):
        """Running twice produces the same result."""
        managed = self._build_tree(tmp_path)
        dest_dir = str(tmp_path)
        content = "etc/**/ 0755 root root\netc/** 0644 root root\n"
        rules = parse_rules(content)

        # First apply
        actions = compute_actions(rules, managed, dest_dir)
        apply_actions(actions)

        # Capture state
        state1 = {}
        for p in managed:
            if os.path.exists(p):
                st = os.stat(p)
                state1[p] = (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)

        # Second apply
        actions = compute_actions(rules, managed, dest_dir)
        apply_actions(actions)

        # Compare
        for p in managed:
            if os.path.exists(p):
                st = os.stat(p)
                state2 = (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
                assert state1[p] == state2, f"not idempotent: {p}"

    def test_chown_pipeline(self, tmp_path, root_check):
        """Full pipeline with ownership changes."""
        user_info = _get_non_root_user()
        group_info = _get_non_root_group()
        if user_info is None or group_info is None:
            pytest.skip("no non-root user/group available")

        user_name, user_uid = user_info
        group_name, group_gid = group_info

        f = tmp_path / "etc" / "test.conf"
        f.parent.mkdir(parents=True)
        f.write_text("")

        content = f"etc/** 0640 {user_name} {group_name}\n"
        rules = parse_rules(content)
        actions = compute_actions(
            rules, [str(f)], str(tmp_path)
        )

        ok, errors = apply_actions(actions)
        assert ok, errors

        st = f.stat()
        assert stat.S_IMODE(st.st_mode) == 0o640
        assert st.st_uid == user_uid
        assert st.st_gid == group_gid
