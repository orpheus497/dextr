# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Package API Exports:** Implemented `dextr/__init__.py` module with public API exports including version metadata, core functions (generate_key_file, load_key_file, encrypt_paths, decrypt_archive), custom exceptions, and format constants. This allows importing dextr functionality programmatically via `from dextr import ...` in addition to CLI usage.
- **Library Documentation:** Added comprehensive Python library usage section to README.md with code examples, function signatures, exception handling patterns, and available constants.

### Changed

- **Core Features:** Updated README.md to include Python Library API as a core feature.

### Fixed

- **License Classification:** Corrected setup.py license classifier from Apache to MIT to match the LICENSE file.

## [1.0.0] - 2025-11-01

### Added

- **Initial Release:** First public version of the `dextr` encryption system.
- **Secure Key Derivation:** Implements HKDF-SHA256 for deriving unique, per-archive encryption keys from a 512-bit master key and random 32-byte salt.
- **Four-Layer Encryption:** Protects files through tar.xz archiving, zlib compression, and four layers of authenticated encryption (ChaCha20-Poly1305 → AES-256-GCM → AES-256-GCM → ChaCha20-Poly1305).
- **Command-Line Interface:** Full-featured argparse-based CLI for non-interactive use in scripts and workflows. Supports `generate`, `encrypt`, `decrypt`, `info`, and `help` commands with --force, --quiet, and --verbose flags.
- **Interactive Help System:** Built-in comprehensive help with topics for security, workflows, examples, and troubleshooting accessible via `dextr help [topic]`.
- **Key & File Formats:** Establishes stable formats for key files (`.dxk`) and encrypted archives (`.dxe`), including magic bytes, versioning, key identifiers, and per-archive salts.
- **Project Structure:** Built as standard Python package with separation between cryptographic core (`dextr/core.py`) and user interface layer (`dextr/cli.py`).
- **Exception Hierarchy:** Defined custom exceptions (DextrError, KeyManagementError, ArchivingError, EncryptionError, DecryptionError) for precise error handling.
- **Input Validation:** Pre-flight validation for file existence, permissions, and output conflicts before performing expensive operations.
- **Multi-Path Archiving:** Support for encrypting multiple files and directories into a single archive with one command.
- **Cross-Platform Support:** Works on Linux, macOS, Windows, and Termux with universal Python launcher scripts.
- **Easy Installation:** Automated install scripts (`install.sh` for Unix/Linux/macOS/Termux, `install.bat` for Windows) with interactive setup and system compatibility checks.
- **Run Scripts:** Provides run.sh (Unix/Linux/macOS/Termux) and run.bat (Windows) for direct execution without installation.
- **Comprehensive Documentation:** Includes GETTING_STARTED.md for beginners, USAGE.md for quick reference, and full technical documentation in README.md.
- **Pip Installation:** Includes setup.py for standard Python package installation with automatic console script creation.