"""
Whitelist support for suppressing known-good dependency findings.

Reads allowlist configuration from pyproject.toml of the scanned project:

    [tool.guarddog.allowlist]

    [[tool.guarddog.allowlist.packages]]
    name = "requests"
    version = "2.28.0"           # optional – omit to match all versions
    rules = ["typosquatting"]    # optional – omit to suppress all rules
    justification = "Verified safe by security team"
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("guarddog")

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class WhitelistEntry:
    name: str
    version: Optional[str] = None
    rules: list[str] = field(default_factory=list)
    justification: Optional[str] = None

    def matches(self, dep_name: str, dep_version: Optional[str], rule: str) -> bool:
        """Check if this entry suppresses a given (dependency, version, rule) triple."""
        if self.name.lower() != dep_name.lower():
            return False
        if self.version is not None and dep_version is not None:
            if self.version != dep_version:
                return False
        if self.rules and rule not in self.rules:
            return False
        return True


class Whitelist:
    def __init__(self, entries: list[WhitelistEntry] | None = None):
        self.entries: list[WhitelistEntry] = entries or []

    def __bool__(self) -> bool:
        return len(self.entries) > 0

    def find_match(
        self, dep_name: str, dep_version: Optional[str], rule: str
    ) -> Optional[WhitelistEntry]:
        """Return the first matching whitelist entry, or None."""
        for entry in self.entries:
            if entry.matches(dep_name, dep_version, rule):
                return entry
        return None

    @classmethod
    def load(cls, pyproject_path: str) -> "Whitelist":
        """Load a Whitelist from a pyproject.toml file."""
        if not os.path.isfile(pyproject_path):
            return cls()

        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        packages = (
            data.get("tool", {}).get("guarddog", {}).get("allowlist", {}).get("packages", [])
        )

        entries: list[WhitelistEntry] = []
        for pkg in packages:
            name = pkg.get("name")
            if not name:
                log.warning("Skipping allowlist entry without 'name'")
                continue
            entries.append(
                WhitelistEntry(
                    name=name,
                    version=pkg.get("version"),
                    rules=pkg.get("rules", []),
                    justification=pkg.get("justification"),
                )
            )

        if entries:
            log.info(
                f"Loaded {len(entries)} allowlist entries from {pyproject_path}"
            )
        return cls(entries)

    @classmethod
    def from_directory(cls, directory: str) -> "Whitelist":
        """Auto-detect pyproject.toml in a directory and load the whitelist."""
        pyproject_path = os.path.join(directory, "pyproject.toml")
        return cls.load(pyproject_path)


def apply_whitelist(
    scan_results: list[dict], whitelist: Whitelist
) -> list[dict]:
    """
    Apply a whitelist to verify-style scan results.

    Each element in scan_results has the shape:
        {"dependency": str, "version": str|None, "result": {issues: int, results: {...}, ...}}

    Whitelisted findings are moved from ``result["results"]`` into
    ``result["suppressed"]`` and the issue count is decremented.
    """
    if not whitelist:
        return scan_results

    for item in scan_results:
        dep_name = item.get("dependency", "")
        dep_version = item.get("version")
        result = item.get("result", {})
        findings = result.get("results", {})

        suppressed: dict[str, dict] = {}
        remaining: dict = {}

        for rule, detail in findings.items():
            match = whitelist.find_match(dep_name, dep_version, rule)
            if match:
                suppressed[rule] = {
                    "detail": detail,
                    "justification": match.justification or "",
                }
                log.info(
                    f"Suppressed rule '{rule}' for {dep_name}"
                    + (f"@{dep_version}" if dep_version else "")
                    + (f" (justification: {match.justification})" if match.justification else "")
                )
            else:
                remaining[rule] = detail

        if suppressed:
            # Recalculate issue count based on remaining findings
            suppressed_count = 0
            for rule, info in suppressed.items():
                detail = info["detail"]
                if isinstance(detail, list):
                    suppressed_count += len(detail)
                else:
                    suppressed_count += 1

            result["results"] = remaining
            result["suppressed"] = suppressed
            result["issues"] = max(0, result.get("issues", 0) - suppressed_count)

    return scan_results


def apply_whitelist_to_scan(
    scan_result: dict, whitelist: Whitelist, dep_name: str, dep_version: Optional[str] = None
) -> dict:
    """
    Apply a whitelist to a single scan-style result dict.

    The result dict has the shape: {issues: int, results: {...}, ...}
    """
    if not whitelist:
        return scan_result

    findings = scan_result.get("results", {})
    suppressed: dict[str, dict] = {}
    remaining: dict = {}

    for rule, detail in findings.items():
        match = whitelist.find_match(dep_name, dep_version, rule)
        if match:
            suppressed[rule] = {
                "detail": detail,
                "justification": match.justification or "",
            }
            log.info(
                f"Suppressed rule '{rule}' for {dep_name}"
                + (f"@{dep_version}" if dep_version else "")
                + (f" (justification: {match.justification})" if match.justification else "")
            )
        else:
            remaining[rule] = detail

    if suppressed:
        suppressed_count = 0
        for rule, info in suppressed.items():
            detail = info["detail"]
            if isinstance(detail, list):
                suppressed_count += len(detail)
            else:
                suppressed_count += 1

        scan_result["results"] = remaining
        scan_result["suppressed"] = suppressed
        scan_result["issues"] = max(0, scan_result.get("issues", 0) - suppressed_count)

    return scan_result
