import os
import typing

from guarddog.analyzer.analyzer import Analyzer
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.scanner import PackageScanner
from guarddog.utils.archives import is_supported_archive
from guarddog.utils.package_info import get_package_info


class PypiPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.PYPI))

    def discover_local_scan_targets(self, path: str) -> set[str]:
        """Discover local package directories via packaging markers or Python heuristics."""
        markers = {"pyproject.toml", "setup.py", "setup.cfg", "PKG-INFO"}
        ignored_dirs = {".git", ".venv", ".lvenv", "venv", "node_modules", "__pycache__"}
        metadata_markers = {"METADATA", "PKG-INFO", "WHEEL", "RECORD"}

        package_dirs = set()
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            if root == path:
                continue

            # Check for standard Python packaging markers
            if markers.intersection(files):
                package_dirs.add(root)
                continue

            # Check for .dist-info/.egg-info metadata directories
            for metadir in (d for d in dirs if d.endswith((".dist-info", ".egg-info"))):
                try:
                    if metadata_markers.intersection(os.listdir(os.path.join(root, metadir))):
                        package_dirs.add(root)
                        break
                except OSError:
                    pass

        if package_dirs:
            return package_dirs

        # Fallback: multiple top-level dirs with .py files
        try:
            top_level = [
                e.path for e in os.scandir(path)
                if e.is_dir(follow_symlinks=False) and e.name not in ignored_dirs and not e.name.startswith(".")
            ]
        except OSError:
            return set()

        if len(top_level) < 2:
            return set()

        result = set()
        for candidate in top_level:
            if any(
                f.endswith(".py")
                for root, _, files in os.walk(candidate)
                for f in files
            ):
                result.add(candidate)

        return result

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> typing.Tuple[dict, str]:
        extract_dir = self.download_package(package_name, directory, version)
        return get_package_info(package_name), extract_dir

    def download_package(self, package_name, directory, version=None) -> str:
        """Downloads the PyPI distribution for a given package and version

        Args:
            package_name (str): name of the package
            directory (str): directory to download package to
            version (str): version of the package

        Raises:
            Exception: "Received status code: " + <not 200> + " from PyPI"
            Exception: "Version " + version + " for package " + package_name + " doesn't exist."
            Exception: "Compressed file for package does not exist."
            Exception: "Error retrieving package: " + <error message>
        Returns:
            Path where the package was extracted
        """

        data = get_package_info(package_name)
        releases = data["releases"]

        if version is None:
            version = data["info"]["version"]

        if version not in releases:
            raise Exception(
                f"Version {version} for package {package_name} doesn't exist."
            )

        files = releases[version]
        url, file_extension = None, None

        for file in files:
            if is_supported_archive(file["filename"]):
                url = file["url"]
                _, file_extension = os.path.splitext(file["filename"])
                break

        if not (url and file_extension):
            raise Exception(
                f"Compressed file for {package_name} does not exist on PyPI."
            )

        # Path to compressed package
        zippath = os.path.join(directory, package_name + file_extension)
        unzippedpath = os.path.join(directory, package_name)
        self.download_compressed(url, zippath, unzippedpath)

        return unzippedpath
