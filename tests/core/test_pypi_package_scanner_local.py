from guarddog.scanners.pypi_package_scanner import PypiPackageScanner


def test_discover_local_scan_targets_from_dist_info(tmp_path):
    root = tmp_path / "deps_api"
    root.mkdir()

    dep_a = root / "dep_a"
    dep_a.mkdir()
    (dep_a / "dep_a-1.0.0.dist-info").mkdir()
    (dep_a / "dep_a-1.0.0.dist-info" / "METADATA").write_text("Name: dep_a\n")

    dep_b = root / "dep_b"
    dep_b.mkdir()
    (dep_b / "setup.py").write_text("from setuptools import setup\n")

    scanner = PypiPackageScanner()
    targets = scanner.discover_local_scan_targets(str(root))

    assert str(dep_a) in targets
    assert str(dep_b) in targets


def test_discover_local_scan_targets_fallback_to_top_level_python_dirs(tmp_path):
    root = tmp_path / "deps_api"
    root.mkdir()

    dep_a = root / "dep_a"
    dep_a.mkdir()
    (dep_a / "module.py").write_text("print('a')\n")

    dep_b = root / "dep_b"
    dep_b.mkdir()
    (dep_b / "module.py").write_text("print('b')\n")

    scanner = PypiPackageScanner()
    targets = scanner.discover_local_scan_targets(str(root))

    assert str(dep_a) in targets
    assert str(dep_b) in targets
