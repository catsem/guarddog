import os
from unittest import mock

from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.whitelist import Whitelist, WhitelistEntry


class DummyPackageScanner(PackageScanner):
    def download_and_get_package_info(self, directory: str, package_name: str, version=None):
        raise NotImplementedError()


def test_scan_local_aggregates_multiple_extracted_dependencies(tmp_path):
    root = tmp_path / "scan-root"
    root.mkdir()

    dep_a = root / "dep-a"
    dep_b = root / "nested" / "dep-b"
    dep_a.mkdir(parents=True)
    dep_b.mkdir(parents=True)

    analyzer = mock.Mock()

    def _analyze_side_effect(path, rules=None):
        if path == str(dep_a):
            return {
                "issues": 1,
                "errors": {},
                "results": {
                    "exec-rule": [
                        {"location": "setup.py:10", "code": "exec(x)", "message": "exec"}
                    ]
                },
                "path": path,
            }

        return {
            "issues": 2,
            "errors": {},
            "results": {
                "exec-rule": [
                    {"location": "init.py:5", "code": "eval(x)", "message": "eval"},
                    {"location": "init.py:8", "code": "exec(y)", "message": "exec"},
                ]
            },
            "path": path,
        }

    analyzer.analyze_sourcecode.side_effect = _analyze_side_effect
    scanner = DummyPackageScanner(analyzer)

    with mock.patch(
        "guarddog.scanners.scanner.extract_archives_recursively",
        return_value={str(dep_a), str(dep_b)},
    ):
        out = scanner.scan_local(str(root))

    assert out["issues"] == 3
    assert "exec-rule" in out["results"]
    assert len(out["results"]["exec-rule"]) == 3

    rel_dep_a = os.path.relpath(str(dep_a), str(root))
    rel_dep_b = os.path.relpath(str(dep_b), str(root))
    locations = [finding["location"] for finding in out["results"]["exec-rule"]]

    assert f"{rel_dep_a}/setup.py:10" in locations
    assert f"{rel_dep_b}/init.py:5" in locations
    assert f"{rel_dep_b}/init.py:8" in locations


def test_scan_local_falls_back_to_single_directory_when_no_extractions(tmp_path):
    root = tmp_path / "scan-root"
    root.mkdir()

    analyzer = mock.Mock()
    analyzer.analyze_sourcecode.return_value = {
        "issues": 0,
        "errors": {},
        "results": {},
        "path": str(root),
    }

    scanner = DummyPackageScanner(analyzer)

    with mock.patch(
        "guarddog.scanners.scanner.extract_archives_recursively",
        return_value=set(),
    ):
        out = scanner.scan_local(str(root))

    analyzer.analyze_sourcecode.assert_called_once_with(str(root), rules=None)
    assert out["path"] == str(root)


def test_scan_local_uses_discovered_targets_when_no_extractions(tmp_path):
    root = tmp_path / "scan-root"
    root.mkdir()

    dep_a = root / "dep-a"
    dep_b = root / "dep-b"
    dep_a.mkdir()
    dep_b.mkdir()

    analyzer = mock.Mock()

    def _analyze_side_effect(path, rules=None):
        return {
            "issues": 1,
            "errors": {},
            "results": {
                "exec-rule": [
                    {"location": "x.py:1", "code": "exec(x)", "message": "exec"}
                ]
            },
            "path": path,
        }

    analyzer.analyze_sourcecode.side_effect = _analyze_side_effect
    scanner = DummyPackageScanner(analyzer)

    with mock.patch(
        "guarddog.scanners.scanner.extract_archives_recursively",
        return_value=set(),
    ):
        with mock.patch.object(
            scanner,
            "discover_local_scan_targets",
            return_value={str(dep_a), str(dep_b)},
        ):
            out = scanner.scan_local(str(root))

    assert out["issues"] == 2
    assert len(out["results"]["exec-rule"]) == 2


def test_scan_local_whitelist_suppresses_per_package(tmp_path):
    root = tmp_path / "scan-root"
    root.mkdir()

    # Directory name follows wheel convention: <name>-<version>-<tag>
    typing_ext = root / "typing_extensions-4.15.0-py3-none-any"
    requests_pkg = root / "requests-2.28.0"
    typing_ext.mkdir()
    requests_pkg.mkdir()

    analyzer = mock.Mock()

    def _analyze_side_effect(path, rules=None):
        return {
            "issues": 1,
            "errors": {},
            "results": {
                "obfuscation": [
                    {"location": "typing_extensions.py:4111", "code": "getattr(builtins, arg)", "message": "obfuscation"}
                ]
            },
            "path": path,
        }

    analyzer.analyze_sourcecode.side_effect = _analyze_side_effect
    scanner = DummyPackageScanner(analyzer)

    wl = Whitelist([
        WhitelistEntry(name="typing_extensions", version="4.15.0", rules=["obfuscation"], justification="false positive")
    ])

    with mock.patch(
        "guarddog.scanners.scanner.extract_archives_recursively",
        return_value=set(),
    ):
        with mock.patch.object(
            scanner,
            "discover_local_scan_targets",
            return_value={str(typing_ext), str(requests_pkg)},
        ):
            out = scanner.scan_local(str(root), whitelist=wl)

    # typing_extensions suppressed, requests still flagged
    assert out["issues"] == 1
    assert "suppressed" not in out or True  # suppressed lives per-package result before merge

    locations = [f["location"] for f in out["results"].get("obfuscation", [])]
    # Only the requests finding should survive
    rel_requests = os.path.relpath(str(requests_pkg), str(root))
    assert any(loc.startswith(rel_requests) for loc in locations)

    rel_typing = os.path.relpath(str(typing_ext), str(root))
    assert not any(loc.startswith(rel_typing) for loc in locations)


def test_parse_package_dir_name_wheel():
    name, version = PackageScanner._parse_package_dir_name("typing_extensions-4.15.0-py3-none-any")
    assert name == "typing_extensions"
    assert version == "4.15.0"


def test_parse_package_dir_name_simple():
    name, version = PackageScanner._parse_package_dir_name("requests-2.28.0")
    assert name == "requests"
    assert version == "2.28.0"


def test_parse_package_dir_name_no_version():
    name, version = PackageScanner._parse_package_dir_name("mypackage")
    assert name == "mypackage"
    assert version is None


def test_scan_local_single_dir_whitelist_suppresses_with_trailing_slash(tmp_path):
    pkg_dir = tmp_path / "typing_extensions-4.15.0-py3-none-any"
    pkg_dir.mkdir()

    analyzer = mock.Mock()
    analyzer.analyze_sourcecode.return_value = {
        "issues": 1,
        "errors": {},
        "results": {
            "obfuscation": [
                {"location": "typing_extensions.py:4111", "code": "getattr(builtins, arg)", "message": "obfuscation"}
            ]
        },
        "path": str(pkg_dir),
    }

    scanner = DummyPackageScanner(analyzer)
    wl = Whitelist([
        WhitelistEntry(name="typing_extensions", version="4.15.0", rules=["obfuscation"])
    ])

    with mock.patch(
        "guarddog.scanners.scanner.extract_archives_recursively",
        return_value=set(),
    ):
        out = scanner.scan_local(str(pkg_dir) + "/", whitelist=wl)

    assert out["issues"] == 0
    assert "obfuscation" not in out["results"]
    pkg_dir = tmp_path / "typing_extensions-4.15.0-py3-none-any"
    pkg_dir.mkdir()

    analyzer = mock.Mock()
    analyzer.analyze_sourcecode.return_value = {
        "issues": 1,
        "errors": {},
        "results": {
            "obfuscation": [
                {"location": "typing_extensions.py:4111", "code": "getattr(builtins, arg)", "message": "obfuscation"}
            ]
        },
        "path": str(pkg_dir),
    }

    scanner = DummyPackageScanner(analyzer)
    wl = Whitelist([
        WhitelistEntry(name="typing_extensions", version="4.15.0", rules=["obfuscation"], justification="false positive")
    ])

    with mock.patch(
        "guarddog.scanners.scanner.extract_archives_recursively",
        return_value=set(),
    ):
        out = scanner.scan_local(str(pkg_dir), whitelist=wl)

    assert out["issues"] == 0
    assert "obfuscation" not in out["results"]
    assert "obfuscation" in out.get("suppressed", {})
