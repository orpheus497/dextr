# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2025-11-08

### Added

- **Comprehensive Test Suite:** Full pytest-based testing infrastructure with unit tests, integration tests, and security tests covering all core functionality
- **CI/CD Pipeline:** GitHub Actions workflows for automated testing (multi-platform, multi-Python version), linting (black, flake8, mypy), and security scanning (bandit, safety)
- **Password-Protected Key Files:** Optional password encryption for .dxk key files using PBKDF2 key derivation for enhanced security
- **Archive Integrity Check Command:** New `check` command to verify archive integrity and perform partial decryption tests without full extraction
- **Examples Directory:** Collection of example scripts demonstrating programmatic API usage for common use cases (basic encryption, batch processing, automated backups)
- **API Documentation:** Sphinx-generated HTML documentation with comprehensive API reference, tutorials, and security guide
- **TOML Parsing Library:** Added tomli dependency for robust TOML configuration file parsing on Python < 3.11
- **Compression Options:** Configurable compression levels (1-9) and optional zlib compression via CLI flags and configuration
- **Enhanced Error Messages:** Improved error messages throughout codebase with context and actionable troubleshooting suggestions
- **Development Security Tools:** Added bandit for security linting and safety for dependency vulnerability scanning

### Changed

- **Minimum Python Version:** Updated minimum Python version from 3.7 to 3.8 (Python 3.7 reached EOL in June 2023)
- **Version Bump:** Updated project version from 1.2.0 to 1.3.0 across all files
- **Python Type Hints:** Completed type annotations across all modules (cli.py, config.py, validation.py) for improved IDE support and static analysis
- **Configuration Module:** Replaced custom TOML parser with tomli library for Python < 3.11, using built-in tomllib for Python 3.11+
- **TOML Configuration:** Enhanced config file support with compression options and password storage preferences
- **MANIFEST.in:** Updated to include examples and documentation directories in source distribution
- **Dependencies:** Updated cryptography to >=41.0.0 for broader compatibility; added tomli>=2.0.0 (conditional on Python < 3.11), bandit>=1.7.0, safety>=2.3.0, coverage>=7.0.0
- **CLI Module:** Fixed type hint error (Optional[any] → Optional[Any]) for better type checking
- **Streaming Module:** Marked as deprecated and moved to experimental subdirectory due to incomplete implementation

### Fixed

- **Security B202 HIGH:** Fixed unsafe tarfile.extractall in experimental/streaming.py by implementing path validation and sanitization
- **Python 3.7/3.8 Compatibility:** Fixed type hint syntax (list[Path] → List[Path]) in experimental module for Python 3.8 compatibility
- **Type Hint Error:** Fixed invalid type hint in cli.py line 85 (lowercase 'any' changed to proper 'Any' type)
- **MANIFEST.in Syntax:** Corrected exclusion syntax for .dev-docs directory (exclude → global-exclude)
- **Windows Permission Handling:** Improved error handling for Windows ACL operations in validation module
- **Missing __main__.py:** Added missing __main__.py to enable 'python -m dextr' execution

### Deprecated

- **Streaming Module:** streaming.py moved to experimental/ subdirectory; not recommended for production use until complete implementation

## [1.2.0] - 2025-11-08

### Added

- **Path Traversal Protection:** Comprehensive validation of all file paths to prevent directory traversal attacks during archiving and extraction
- **Input Validation Framework:** New validation.py module with sanitization for paths, key files, archives, and output destinations
- **Key File Permission Enforcement:** Automatic setting of restrictive permissions (0600 on Unix, equivalent ACLs on Windows) for generated key files
- **Atomic File Operations:** Write-to-temporary-then-rename pattern for all file writes to prevent corruption on interruption
- **Secure Temporary File Handling:** Enhanced temporary file creation with proper cleanup in all error paths
- **Progress Callback Support:** Added optional progress_callback parameter to encrypt_paths() and decrypt_archive() for real-time progress monitoring
- **Archive Size Limits:** Configurable maximum archive size validation to prevent resource exhaustion attacks
- **Configuration File Support:** New config.py module supporting ~/.dextr.conf and ./.dextr.conf with TOML format for user preferences
- **Logging Infrastructure:** Comprehensive logging system with configurable levels, file output, and security event tracking
- **Security Event Logging:** Dedicated logging for security-relevant events (key generation, encryption, decryption operations)
- **Archive Info Function:** Added get_archive_info() to read archive metadata without decryption
- **Streaming Module:** New streaming.py module for future memory-efficient large file processing
- **Modern Python Packaging:** Added pyproject.toml with PEP 621 metadata and tool configurations
- **Development Dependencies:** New requirements-dev.txt with pytest, black, mypy, flake8, sphinx
- **Security Policy:** Comprehensive SECURITY.md with vulnerability reporting process and security best practices
- **Contribution Guidelines:** Detailed CONTRIBUTING.md with development setup, coding standards, and PR process
- **Code of Conduct:** Added CODE_OF_CONDUCT.md based on Contributor Covenant v2.1
- **Type Hints:** Added complete type annotations to all functions in core.py with typing module imports
- **ValidationError Exception:** New exception type for input validation failures

### Changed

- **Core Module Security Hardening:** Complete refactor of core.py with security fixes, proper resource cleanup, and comprehensive error handling
- **Key Generation:** Enhanced generate_key_file() with permission enforcement and validation
- **Key Loading:** Improved load_key_file() with comprehensive validation and security event logging
- **Encryption Pipeline:** Updated encrypt_paths() with progress tracking, validation, and atomic writes
- **Decryption Pipeline:** Enhanced decrypt_archive() with member validation, path sanitization, and progress tracking
- **Resource Management:** Fixed file descriptor leaks by ensuring proper cleanup in all exception paths
- **Memory Management:** Added explicit deletion of large buffers to free memory during encryption/decryption
- **Error Messages:** Improved error messages with context and actionable suggestions
- **Documentation:** Updated README.md to include ValidationError in import examples and fix import statement bugs
- **Package Metadata:** Updated version to 1.2.0 across all relevant files
- **MANIFEST.in:** Added new documentation files (SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, GETTING_STARTED.md, USAGE.md)
- **Dependencies:** Added tqdm>=4.66.0 for progress bar support

### Fixed

- **CVE: Path Traversal Vulnerability:** Fixed critical vulnerability allowing directory traversal during archive extraction
- **CVE: Resource Leak:** Fixed file descriptor leak when exceptions occur during archive creation
- **CVE: Insufficient Permission Controls:** Key files now have restrictive permissions enforced automatically
- **Documentation Bug:** Fixed missing ArchivingError in README.md example imports (line 298)
- **Documentation Bug:** Removed duplicate "# dextr" header at end of README.md
- **Temporary File Cleanup:** Fixed incomplete cleanup when removal fails by adding proper error handling
- **Archive Member Validation:** Added validation to detect and prevent malicious tar archive members

### Security

- **Path Sanitization:** All archive members validated and sanitized before extraction
- **Symlink Protection:** Restricted symlink following in security-sensitive contexts
- **Input Validation:** Comprehensive validation of all user-provided paths and parameters
- **Audit Logging:** Security events now logged for forensics and monitoring
- **Permission Hardening:** Key files automatically protected with minimal necessary permissions
- **Atomic Writes:** Prevents partial file writes that could leave system in inconsistent state

### Performance

- **Memory Efficiency:** Explicit buffer cleanup reduces memory usage during encryption/decryption
- **Progress Feedback:** User experience improved with progress tracking for long operations
- **Optimized Validation:** Early validation prevents expensive operations on invalid inputs

### Developer Experience

- **Type Safety:** Complete type hints enable better IDE support and static analysis
- **Testing Framework:** Infrastructure for comprehensive test suite with pytest
- **Code Quality Tools:** Configuration for black, mypy, flake8 in pyproject.toml
- **Documentation:** Improved inline documentation with detailed docstrings
- **Logging:** Debug logging throughout codebase for troubleshooting
- **Modular Architecture:** Separated concerns into validation, config, logging, streaming modules

## [1.1.0] - 2025-11-08

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