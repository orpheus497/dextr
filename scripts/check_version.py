#!/usr/bin/env python3
"""
Version Consistency Checker for dextr

This script verifies that version numbers are consistent across all
project files. Run this before creating releases.

Usage:
    python scripts/check_version.py [--expected-version X.Y.Z]

Exit codes:
    0 - All versions consistent
    1 - Version inconsistencies found
    2 - Error running checks
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Project root (assuming script is in scripts/ directory)
PROJECT_ROOT = Path(__file__).parent.parent


def get_version_from_version_py() -> str:
    """Extract version from dextr/version.py"""
    version_file = PROJECT_ROOT / "dextr" / "version.py"
    content = version_file.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    if not match:
        raise ValueError("Could not find __version__ in version.py")
    return match.group(1)


def check_file_versions() -> Tuple[bool, List[str]]:
    """
    Check version consistency across all project files.

    Returns:
        Tuple of (all_consistent, list_of_issues)
    """
    issues = []
    canonical_version = get_version_from_version_py()
    print(f"Canonical version (from dextr/version.py): {canonical_version}")
    print()

    # File checks with regex patterns
    checks: Dict[Path, List[Tuple[str, str]]] = {
        PROJECT_ROOT / "pyproject.toml": [
            (r'version\s*=\s*"([^"]+)"', "pyproject.toml version field"),
        ],
        PROJECT_ROOT / "README.md": [
            (r'D E X T R\s+v(\d+\.\d+\.\d+)', "README.md banner version"),
        ],
        PROJECT_ROOT / "CHANGELOG.md": [
            # Check that Unreleased section exists
            (r'\[Unreleased\]', "CHANGELOG.md Unreleased section"),
        ],
        PROJECT_ROOT / "setup.py": [
            # setup.py uses __version__ import, so it should auto-sync
            (r'from dextr\.version import __version__', "setup.py imports version"),
        ],
    }

    for file_path, patterns in checks.items():
        if not file_path.exists():
            issues.append(f"Missing file: {file_path}")
            continue

        content = file_path.read_text(encoding="utf-8")

        for pattern, description in patterns:
            match = re.search(pattern, content)
            if not match:
                issues.append(f"{description}: Pattern not found")
                continue

            # For version patterns, check if they match canonical
            if "version" in description.lower() and len(match.groups()) > 0:
                found_version = match.group(1)
                if found_version != canonical_version:
                    issues.append(
                        f"{description}: Expected {canonical_version}, "
                        f"found {found_version}"
                    )
                else:
                    print(f"✓ {description}: {found_version}")
            else:
                print(f"✓ {description}: Found")

    # Check Python version requirements consistency
    print()
    print("Checking Python version requirements...")

    python_version_files = {
        PROJECT_ROOT / "setup.py": r'python_requires\s*=\s*"([^"]+)"',
        PROJECT_ROOT / "pyproject.toml": r'requires-python\s*=\s*"([^"]+)"',
        PROJECT_ROOT / "README.md": r'Python\s+(\d+\.\d+)\s+or\s+higher',
    }

    python_versions = {}
    for file_path, pattern in python_version_files.items():
        if file_path.exists():
            content = file_path.read_text(encoding="utf-8")
            match = re.search(pattern, content)
            if match:
                python_versions[file_path.name] = match.group(1)

    # Normalize versions (e.g., ">=3.8" vs "3.8")
    normalized = {k: v.replace(">=", "") for k, v in python_versions.items()}

    if len(set(normalized.values())) > 1:
        issues.append(f"Python version inconsistency: {dict(python_versions)}")
    else:
        print(f"✓ Python version consistent: {list(normalized.values())[0]}")

    # Check cryptography version consistency
    print()
    print("Checking cryptography version requirements...")

    crypto_files = {
        PROJECT_ROOT / "requirements.txt": r'cryptography>=([0-9.]+)',
        PROJECT_ROOT / "pyproject.toml": r'cryptography>=([0-9.]+)',
    }

    crypto_versions = {}
    for file_path, pattern in crypto_files.items():
        if file_path.exists():
            content = file_path.read_text(encoding="utf-8")
            match = re.search(pattern, content)
            if match:
                crypto_versions[file_path.name] = match.group(1)

    if len(set(crypto_versions.values())) > 1:
        issues.append(f"Cryptography version inconsistency: {crypto_versions}")
    else:
        print(f"✓ Cryptography version consistent: {list(crypto_versions.values())[0]}")

    print()
    return len(issues) == 0, issues


def main() -> int:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Check version consistency across dextr project files"
    )
    parser.add_argument(
        "--expected-version",
        help="Expected version number (if not specified, uses dextr/version.py)",
    )
    args = parser.parse_args()

    try:
        print("=" * 70)
        print("dextr Version Consistency Checker")
        print("=" * 70)
        print()

        all_consistent, issues = check_file_versions()

        if all_consistent:
            print()
            print("=" * 70)
            print("✓ SUCCESS: All versions are consistent!")
            print("=" * 70)
            return 0
        else:
            print()
            print("=" * 70)
            print("✗ FAILURE: Version inconsistencies detected:")
            print("=" * 70)
            for issue in issues:
                print(f"  - {issue}")
            print()
            print("Please fix these issues before releasing.")
            return 1

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
