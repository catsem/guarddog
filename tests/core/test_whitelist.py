import os
import tempfile
import pytest
from guarddog.utils.whitelist import (
    Whitelist,
    WhitelistEntry,
    apply_whitelist,
    apply_whitelist_to_scan,
)


class TestWhitelistEntry:
    def test_matches_name_only(self):
        entry = WhitelistEntry(name="requests")
        assert entry.matches("requests", "2.28.0", "typosquatting")
        assert entry.matches("requests", None, "code-execution")
        assert not entry.matches("flask", "1.0", "typosquatting")

    def test_matches_case_insensitive_name(self):
        entry = WhitelistEntry(name="Requests")
        assert entry.matches("requests", "1.0", "typosquatting")
        assert entry.matches("REQUESTS", "1.0", "typosquatting")

    def test_matches_with_version(self):
        entry = WhitelistEntry(name="requests", version="2.28.0")
        assert entry.matches("requests", "2.28.0", "typosquatting")
        assert not entry.matches("requests", "2.27.0", "typosquatting")
        # version=None in dependency means unknown – should still match
        assert entry.matches("requests", None, "typosquatting")

    def test_matches_with_rules(self):
        entry = WhitelistEntry(name="requests", rules=["typosquatting", "code-execution"])
        assert entry.matches("requests", "1.0", "typosquatting")
        assert entry.matches("requests", "1.0", "code-execution")
        assert not entry.matches("requests", "1.0", "cmd-overwrite")

    def test_matches_empty_rules_matches_all(self):
        entry = WhitelistEntry(name="requests", rules=[])
        assert entry.matches("requests", "1.0", "any-rule")

    def test_matches_version_and_rules(self):
        entry = WhitelistEntry(name="requests", version="2.28.0", rules=["typosquatting"])
        assert entry.matches("requests", "2.28.0", "typosquatting")
        assert not entry.matches("requests", "2.28.0", "code-execution")
        assert not entry.matches("requests", "2.27.0", "typosquatting")


class TestWhitelist:
    def test_empty_whitelist_is_falsy(self):
        wl = Whitelist()
        assert not wl

    def test_non_empty_whitelist_is_truthy(self):
        wl = Whitelist([WhitelistEntry(name="requests")])
        assert wl

    def test_find_match(self):
        wl = Whitelist([
            WhitelistEntry(name="requests", justification="safe"),
            WhitelistEntry(name="flask", rules=["typosquatting"]),
        ])
        match = wl.find_match("requests", "1.0", "any-rule")
        assert match is not None
        assert match.justification == "safe"

        match = wl.find_match("flask", "1.0", "typosquatting")
        assert match is not None

        match = wl.find_match("flask", "1.0", "code-execution")
        assert match is None

        match = wl.find_match("django", "1.0", "typosquatting")
        assert match is None

    def test_load_from_pyproject(self):
        toml_content = """\
[tool.guarddog.allowlist]

[[tool.guarddog.allowlist.packages]]
name = "requests"
version = "2.28.0"
rules = ["typosquatting"]
justification = "Verified safe"

[[tool.guarddog.allowlist.packages]]
name = "flask"
justification = "Internal package"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "pyproject.toml")
            with open(path, "w") as f:
                f.write(toml_content)

            wl = Whitelist.load(path)
            assert len(wl.entries) == 2
            assert wl.entries[0].name == "requests"
            assert wl.entries[0].version == "2.28.0"
            assert wl.entries[0].rules == ["typosquatting"]
            assert wl.entries[0].justification == "Verified safe"
            assert wl.entries[1].name == "flask"
            assert wl.entries[1].version is None
            assert wl.entries[1].rules == []

    def test_load_nonexistent_file(self):
        wl = Whitelist.load("/nonexistent/pyproject.toml")
        assert not wl

    def test_load_pyproject_without_allowlist(self):
        toml_content = """\
[tool.other]
key = "value"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "pyproject.toml")
            with open(path, "w") as f:
                f.write(toml_content)

            wl = Whitelist.load(path)
            assert not wl

    def test_from_directory(self):
        toml_content = """\
[[tool.guarddog.allowlist.packages]]
name = "requests"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "pyproject.toml")
            with open(path, "w") as f:
                f.write(toml_content)

            wl = Whitelist.from_directory(tmpdir)
            assert len(wl.entries) == 1

    def test_from_directory_no_pyproject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wl = Whitelist.from_directory(tmpdir)
            assert not wl


class TestApplyWhitelist:
    def _make_results(self):
        return [
            {
                "dependency": "requests",
                "version": "2.28.0",
                "result": {
                    "issues": 3,
                    "results": {
                        "typosquatting": "Package name looks suspicious",
                        "code-execution": [
                            {"location": "setup.py:1", "code": "os.system('rm -rf /')", "message": "exec call"},
                            {"location": "setup.py:5", "code": "eval(x)", "message": "eval call"},
                        ],
                    },
                    "errors": {},
                },
            },
            {
                "dependency": "flask",
                "version": "2.0.0",
                "result": {
                    "issues": 1,
                    "results": {
                        "typosquatting": "Looks like a typosquat",
                    },
                    "errors": {},
                },
            },
        ]

    def test_no_whitelist_returns_unchanged(self):
        results = self._make_results()
        wl = Whitelist()
        out = apply_whitelist(results, wl)
        assert out[0]["result"]["issues"] == 3
        assert out[1]["result"]["issues"] == 1

    def test_suppress_single_rule(self):
        results = self._make_results()
        wl = Whitelist([WhitelistEntry(name="requests", rules=["typosquatting"])])
        out = apply_whitelist(results, wl)
        r = out[0]["result"]
        assert "typosquatting" not in r["results"]
        assert "typosquatting" in r["suppressed"]
        assert r["issues"] == 2  # code-execution still has 2 findings

    def test_suppress_all_rules_for_dependency(self):
        results = self._make_results()
        wl = Whitelist([WhitelistEntry(name="requests")])
        out = apply_whitelist(results, wl)
        r = out[0]["result"]
        assert r["results"] == {}
        assert r["issues"] == 0
        assert "typosquatting" in r["suppressed"]
        assert "code-execution" in r["suppressed"]

    def test_suppress_with_version_filter(self):
        results = self._make_results()
        wl = Whitelist([WhitelistEntry(name="requests", version="1.0.0")])
        out = apply_whitelist(results, wl)
        # version doesn't match, no suppression
        assert out[0]["result"]["issues"] == 3
        assert "suppressed" not in out[0]["result"]

    def test_justification_preserved(self):
        results = self._make_results()
        wl = Whitelist([WhitelistEntry(name="flask", justification="Known safe")])
        out = apply_whitelist(results, wl)
        r = out[1]["result"]
        assert r["suppressed"]["typosquatting"]["justification"] == "Known safe"
        assert r["issues"] == 0

    def test_other_dependencies_unaffected(self):
        results = self._make_results()
        wl = Whitelist([WhitelistEntry(name="requests")])
        out = apply_whitelist(results, wl)
        assert out[1]["result"]["issues"] == 1
        assert "suppressed" not in out[1]["result"]


class TestApplyWhitelistToScan:
    def test_suppress_scan_result(self):
        result = {
            "package": "requests",
            "issues": 2,
            "results": {
                "typosquatting": "suspicious",
                "code-execution": [
                    {"location": "a.py:1", "code": "exec(x)", "message": "exec"},
                ],
            },
        }
        wl = Whitelist([WhitelistEntry(name="requests", rules=["typosquatting"])])
        out = apply_whitelist_to_scan(result, wl, "requests", "1.0")
        assert "typosquatting" not in out["results"]
        assert "typosquatting" in out["suppressed"]
        assert out["issues"] == 1

    def test_no_match_leaves_unchanged(self):
        result = {
            "package": "requests",
            "issues": 1,
            "results": {"typosquatting": "suspicious"},
        }
        wl = Whitelist([WhitelistEntry(name="flask")])
        out = apply_whitelist_to_scan(result, wl, "requests", "1.0")
        assert out["issues"] == 1
        assert "suppressed" not in out
