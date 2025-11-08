#!/usr/bin/env python
"""
dextr/cli.py

Command-line interface for the dextr application.
This module handles all user interaction, argument parsing, and formatting of output.
It calls the core cryptographic engine and presents results to the user.
Cross-platform compatible: Linux, macOS, Windows, Termux.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Any, NoReturn, Optional

try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

from dextr.config import get_max_archive_size, load_config
from dextr.core import (
    check_archive_integrity,
    decrypt_archive,
    encrypt_paths,
    generate_key_file,
    get_archive_info,
    load_key_file,
)
from dextr.exceptions import (
    ArchivingError,
    DecryptionError,
    DextrError,
    EncryptionError,
    KeyManagementError,
    ValidationError,
)
from dextr.key_protection import get_password_strength, prompt_password, read_password_from_file
from dextr.logging_config import get_logger, setup_logging
from dextr.version import __version__

# Get logger for this module
logger = get_logger(__name__)


def format_bytes(size: int) -> str:
    """Format byte size to human-readable string."""
    for unit in ["bytes", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            if unit == "bytes":
                return f"{size} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def print_banner() -> None:
    """Print the application banner."""
    print("╔══════════════════════════════════════════════════╗")
    print(f"║              D E X T R  v{__version__}                   ║")
    print("║      Secure Archiving & Encryption System        ║")
    print("║            Created by orpheus497                 ║")
    print("╚══════════════════════════════════════════════════╝")
    print()


def error_exit(message: str, exit_code: int = 1) -> NoReturn:
    """Print error message and exit."""
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(exit_code)


def get_password_from_args(args: argparse.Namespace) -> Optional[str]:
    """
    Get password from command-line arguments.

    Checks for --password or --password-file flags and returns the password.

    Args:
        args: Parsed command-line arguments

    Returns:
        Password string or None if no password specified

    Raises:
        Exits on error
    """
    if getattr(args, "password", False):
        try:
            return prompt_password()
        except KeyManagementError as e:
            error_exit(str(e))
    elif getattr(args, "password_file", None):
        try:
            return read_password_from_file(args.password_file)
        except KeyManagementError as e:
            error_exit(str(e))
    return None


class ProgressCallback:
    """Progress callback wrapper for tqdm integration."""

    def __init__(self, quiet: bool = False):
        """
        Initialize progress callback.

        Args:
            quiet: If True, suppress all progress output
        """
        self.quiet = quiet
        self.pbar: Optional[Any] = None
        self.current_stage = ""

    def __call__(self, stage: str, current: int, total: int) -> None:
        """
        Progress callback function.

        Args:
            stage: Current operation stage
            current: Current progress value
            total: Total progress value
        """
        if self.quiet:
            return

        # If stage changed, update description
        if stage != self.current_stage:
            if self.pbar is not None:
                self.pbar.close()

            self.current_stage = stage

            # Create new progress bar if tqdm is available
            if HAS_TQDM:
                self.pbar = tqdm(
                    total=total,
                    desc=stage,
                    unit="%",
                    bar_format="{desc}: {percentage:3.0f}%|{bar}| [{elapsed}<{remaining}]",
                )
            else:
                # Fallback: simple text output
                print(f"[*] {stage}...")

        # Update progress bar
        if self.pbar is not None and HAS_TQDM:
            self.pbar.n = current
            self.pbar.refresh()

        # If complete, close progress bar
        if current >= total and self.pbar is not None:
            if HAS_TQDM:
                self.pbar.close()
            self.pbar = None

    def close(self) -> None:
        """Close any open progress bars."""
        if self.pbar is not None and HAS_TQDM:
            self.pbar.close()
            self.pbar = None


def cmd_generate(args: argparse.Namespace) -> int:
    """Handle the 'generate' command."""
    key_path = args.output if args.output else "dextrkey.dxk"

    # Check if file already exists
    if os.path.exists(key_path) and not args.force:
        error_exit(f"Key file '{key_path}' already exists. Use --force to overwrite.")

    # Get password if requested
    password = None
    if getattr(args, "password", False):
        try:
            password = prompt_password("Enter password to protect key file: ", confirm=True)
            # Show password strength
            strength = get_password_strength(password)
            print(f"Password strength: {strength['strength']} (score: {strength['score']}/100)")
            if strength["strength"] == "weak":
                print("⚠️  Warning: Consider using a stronger password")
        except KeyManagementError as e:
            error_exit(str(e))
    elif getattr(args, "password_file", None):
        try:
            password = read_password_from_file(args.password_file)
        except KeyManagementError as e:
            error_exit(str(e))

    try:
        metadata = generate_key_file(key_path, password=password)
        print(f"Success: Generated new key file at '{key_path}'")
        print(f"  Created by: {metadata.get('created_by', 'unknown')}")
        print(f"  Created at: {metadata.get('created_at', 'unknown')}")
        print(f"  Key ID: {metadata.get('key_id', 'unknown')}")
        if password:
            print("  Protection: Password-protected")
        print()
        print(
            "⚠️  IMPORTANT: Back up this key file securely. "
            "Without it, your encrypted data cannot be recovered."
        )
        if password:
            print("⚠️  IMPORTANT: Remember your password. Without it, the key file cannot be used.")
        return 0
    except KeyManagementError as e:
        error_exit(str(e))
    except Exception as e:
        error_exit(f"Unexpected error generating key file: {e}")


def cmd_encrypt(args: argparse.Namespace, config: dict) -> int:
    """Handle the 'encrypt' command."""
    key_path = args.key
    input_paths = args.input
    output_path = args.output

    # Validate key file exists
    if not os.path.exists(key_path):
        error_exit(f"Key file not found: {key_path}")

    # Validate all input paths exist
    for path in input_paths:
        if not os.path.exists(path):
            error_exit(f"Input path not found: {path}")

    # Check if output file already exists
    if os.path.exists(output_path) and not args.force:
        error_exit(f"Output file '{output_path}' already exists. Use --force to overwrite.")

    # Get password if needed
    password = get_password_from_args(args)

    try:
        # Load the key
        if not args.quiet:
            print(f"[*] Loading key from '{key_path}'...")
        master_key, metadata = load_key_file(key_path, password=password)

        if args.verbose:
            print(f"    Key ID: {metadata.get('key_id', 'unknown')}")

        # Perform encryption with progress tracking
        if not args.quiet:
            print(f"[*] Archiving and encrypting {len(input_paths)} path(s)...")

        # Get max archive size from config
        max_size = get_max_archive_size(config)

        # Create progress callback
        progress = ProgressCallback(quiet=args.quiet)

        try:
            encrypt_paths(
                input_paths,
                output_path,
                master_key,
                max_size=max_size,
                progress_callback=progress if not args.quiet else None,
            )
        finally:
            progress.close()

        # Report success
        output_size = os.path.getsize(output_path)
        print(f"Success: Archive encrypted to '{output_path}'")
        print(f"    Encrypted size: {format_bytes(output_size)}")

        return 0

    except KeyManagementError as e:
        error_exit(f"Key error: {e}")
    except ArchivingError as e:
        error_exit(f"Archiving error: {e}")
    except EncryptionError as e:
        error_exit(f"Encryption error: {e}")
    except ValidationError as e:
        error_exit(f"Validation error: {e}")
    except DextrError as e:
        error_exit(str(e))
    except Exception as e:
        error_exit(f"Unexpected error during encryption: {e}")


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Handle the 'decrypt' command."""
    key_path = args.key
    input_path = args.input
    output_dir = args.output

    # Validate key file exists
    if not os.path.exists(key_path):
        error_exit(f"Key file not found: {key_path}")

    # Validate input file exists
    if not os.path.exists(input_path):
        error_exit(f"Encrypted file not found: {input_path}")

    # Check if output directory exists
    if os.path.exists(output_dir):
        if not os.path.isdir(output_dir):
            error_exit(f"Output path '{output_dir}' exists but is not a directory.")
        if os.listdir(output_dir) and not args.force:
            error_exit(
                f"Output directory '{output_dir}' is not empty. Use --force to extract anyway."
            )
    else:
        # Create output directory
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            error_exit(f"Failed to create output directory: {e}")

    # Get password if needed
    password = get_password_from_args(args)

    try:
        # Load the key
        if not args.quiet:
            print(f"[*] Loading key from '{key_path}'...")
        master_key, metadata = load_key_file(key_path, password=password)

        if args.verbose:
            print(f"    Key ID: {metadata.get('key_id', 'unknown')}")

        # Perform decryption with progress tracking
        if not args.quiet:
            print(f"[*] Decrypting and extracting '{input_path}'...")

        # Create progress callback
        progress = ProgressCallback(quiet=args.quiet)

        try:
            decrypt_archive(
                input_path,
                output_dir,
                master_key,
                progress_callback=progress if not args.quiet else None,
            )
        finally:
            progress.close()

        # Report success
        print(f"Success: Archive decrypted and extracted to '{output_dir}'")

        return 0

    except KeyManagementError as e:
        error_exit(f"Key error: {e}")
    except DecryptionError as e:
        error_exit(f"Decryption error: {e}")
    except ValidationError as e:
        error_exit(f"Validation error: {e}")
    except DextrError as e:
        error_exit(str(e))
    except Exception as e:
        error_exit(f"Unexpected error during decryption: {e}")


def cmd_info(args: argparse.Namespace) -> int:
    """Handle the 'info' command."""
    key_path = args.key

    # Validate key file exists
    if not os.path.exists(key_path):
        error_exit(f"Key file not found: {key_path}")

    # Get password if needed
    password = get_password_from_args(args)

    try:
        master_key, metadata = load_key_file(key_path, password=password)

        print(f"Key File: {key_path}")
        print(f"  Magic: {metadata.get('magic', 'unknown')}")
        print(f"  Version: {metadata.get('version', 'unknown')}")
        print(f"  Created by: {metadata.get('created_by', 'unknown')}")
        print(f"  Created at: {metadata.get('created_at', 'unknown')}")
        print(f"  Key ID: {metadata.get('key_id', 'unknown')}")
        print(f"  Master Key Length: {len(master_key) * 8} bits")

        return 0

    except KeyManagementError as e:
        error_exit(f"Key error: {e}")
    except DextrError as e:
        error_exit(str(e))
    except Exception as e:
        error_exit(f"Unexpected error reading key file: {e}")


def cmd_verify(args: argparse.Namespace) -> int:
    """Handle the 'verify' command - verify archive without decrypting."""
    archive_path = args.input

    # Validate archive file exists
    if not os.path.exists(archive_path):
        error_exit(f"Archive file not found: {archive_path}")

    try:
        info = get_archive_info(archive_path)

        print(f"Archive: {archive_path}")
        print(f"  Format Version: {info['format_version']}")
        print(f"  Key ID: {info['key_id']}")
        print(f"  File Size: {format_bytes(info['file_size'])}")
        print(f"  Encrypted Data Size: {format_bytes(info['encrypted_size'])}")
        print(f"  Salt: {info['salt'][:32]}...")
        print()
        print("✓ Archive structure is valid")

        return 0

    except DecryptionError as e:
        error_exit(f"Verification error: {e}")
    except DextrError as e:
        error_exit(str(e))
    except Exception as e:
        error_exit(f"Unexpected error verifying archive: {e}")


def cmd_list(args: argparse.Namespace) -> int:
    """Handle the 'list' command - list archive contents without extracting."""
    key_path = args.key
    input_path = args.input

    # Validate key file exists
    if not os.path.exists(key_path):
        error_exit(f"Key file not found: {key_path}")

    # Validate input file exists
    if not os.path.exists(input_path):
        error_exit(f"Archive file not found: {input_path}")

    # Get password if needed
    password = get_password_from_args(args)

    try:
        import tempfile

        # Load the key
        if not args.quiet:
            print(f"[*] Loading key from '{key_path}'...")
        master_key, metadata = load_key_file(key_path, password=password)

        # For listing, we need to decrypt but not extract
        # We'll use a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            if not args.quiet:
                print("[*] Decrypting archive (temporary)...")

            # Decrypt to temp directory
            decrypt_archive(input_path, temp_dir, master_key)

            print(f"\nContents of '{input_path}':")
            print("-" * 60)

            # List all files recursively
            total_size = 0
            file_count = 0
            dir_count = 0

            for item in sorted(Path(temp_dir).rglob("*")):
                if item.is_file():
                    size = item.stat().st_size
                    total_size += size
                    file_count += 1
                    rel_path = item.relative_to(temp_dir)
                    print(f"  {format_bytes(size):>12}  {rel_path}")
                elif item.is_dir() and item != Path(temp_dir):
                    dir_count += 1
                    rel_path = item.relative_to(temp_dir)
                    print(f"  {'<DIR>':>12}  {rel_path}/")

            print("-" * 60)
            print(f"Total: {file_count} file(s), {dir_count} dir(s), {format_bytes(total_size)}")

        return 0

    except KeyManagementError as e:
        error_exit(f"Key error: {e}")
    except DecryptionError as e:
        error_exit(f"Decryption error: {e}")
    except DextrError as e:
        error_exit(str(e))
    except Exception as e:
        error_exit(f"Unexpected error listing archive: {e}")


def cmd_check(args: argparse.Namespace) -> int:
    """Handle the 'check' command - check archive integrity with key."""
    key_path = args.key
    input_path = args.input

    # Validate key file exists
    if not os.path.exists(key_path):
        error_exit(f"Key file not found: {key_path}")

    # Validate input file exists
    if not os.path.exists(input_path):
        error_exit(f"Archive file not found: {input_path}")

    # Get password if needed
    password = get_password_from_args(args)

    # Determine check type
    quick = getattr(args, "quick", False)

    try:
        # Load the key
        if not args.quiet:
            print(f"[*] Loading key from '{key_path}'...")
        master_key, metadata = load_key_file(key_path, password=password)

        if args.verbose:
            print(f"    Key ID: {metadata.get('key_id', 'unknown')}")

        # Perform integrity check
        if not args.quiet:
            check_type = "quick" if quick else "full"
            print(f"[*] Performing {check_type} integrity check on '{input_path}'...")

        result = check_archive_integrity(input_path, master_key, quick=quick)

        # Display results
        print(f"\nIntegrity Check Results for '{input_path}':")
        print("-" * 60)
        print(f"  Header Valid:           {'✓ Yes' if result['header_valid'] else '✗ No'}")
        print(f"  Key Match:              {'✓ Yes' if result['key_match'] else '✗ No'}")
        print(f"  Decryption Success:     {'✓ Yes' if result['decrypt_success'] else '✗ No'}")

        if not quick:
            print(
                f"  Full Decrypt Success:   {'✓ Yes' if result['full_decrypt_success'] else '✗ No'}"
            )

        print("-" * 60)

        if result["valid"]:
            print("✓ Archive integrity check PASSED")
            print("\nThe archive appears to be valid and can be decrypted with this key.")
            return 0
        else:
            print("✗ Archive integrity check FAILED")
            if result.get("error"):
                print(f"\nError: {result['error']}")
            return 1

    except KeyManagementError as e:
        error_exit(f"Key error: {e}")
    except DecryptionError as e:
        error_exit(f"Integrity check error: {e}")
    except DextrError as e:
        error_exit(str(e))
    except Exception as e:
        error_exit(f"Unexpected error during integrity check: {e}")


def cmd_help(args: argparse.Namespace) -> int:
    """Handle the 'help' command - show detailed usage guide."""
    topic = args.topic if hasattr(args, "topic") else None

    if topic == "security":
        print("╔══════════════════════════════════════════════════╗")
        print("║          dextr Security Information              ║")
        print("╚══════════════════════════════════════════════════╝")
        print()
        print("Encryption Architecture:")
        print("  • Master Key: 512-bit random key stored in .dxk file")
        print("  • Key Derivation: HKDF-SHA256 with unique salt per archive")
        print("  • Layer Keys: Four 256-bit keys derived for each archive")
        print()
        print("Encryption Layers (defense-in-depth):")
        print("  1. tar.xz archiving (LZMA compression)")
        print("  2. zlib compression")
        print("  3. ChaCha20-Poly1305 AEAD encryption")
        print("  4. AES-256-GCM AEAD encryption")
        print("  5. AES-256-GCM AEAD encryption")
        print("  6. ChaCha20-Poly1305 AEAD encryption")
        print()
        print("Security Properties:")
        print("  • Authenticated Encryption: Detects tampering automatically")
        print("  • Unique Keys: Every archive uses unique derived keys")
        print("  • No Key Reuse: Fresh nonces for every encryption operation")
        print("  • Key ID Verification: Wrong key detected immediately")
        print()
        print("Best Practices:")
        print("  ✓ Back up key files in multiple secure locations")
        print("  ✓ Keep keys separate from encrypted data")
        print("  ✓ Use different keys for different purposes")
        print("  ✓ Test decryption after encryption")
        print("  ✓ Protect key files like passwords")
        print()

    elif topic == "workflow":
        print("╔══════════════════════════════════════════════════╗")
        print("║          dextr Typical Workflows                 ║")
        print("╚══════════════════════════════════════════════════╝")
        print()
        print("Workflow 1: Quick Backup")
        print("  $ dextr generate backup_key.dxk")
        print("  $ dextr encrypt -k backup_key.dxk -i ~/Documents -o backup.dxe")
        print("  $ dextr decrypt -k backup_key.dxk -i backup.dxe -o ~/restored")
        print()
        print("Workflow 2: Secure File Transfer")
        print("  1. Create key and share it securely (USB, in-person)")
        print("  2. Encrypt files: dextr encrypt -k shared.dxk -i files/ -o transfer.dxe")
        print("  3. Send .dxe file via email/cloud (safe without key)")
        print("  4. Recipient decrypts: dextr decrypt -k shared.dxk -i transfer.dxe -o received/")
        print()
        print("Workflow 3: Scheduled Backups")
        print("  # Create backup script:")
        print("  #!/bin/bash")
        print("  DATE=$(date +%Y%m%d)")
        print("  dextr encrypt -k ~/.backup_key.dxk -i ~/important -o backup_$DATE.dxe --quiet")
        print()
        print("  # Add to crontab:")
        print("  0 2 * * * /path/to/backup-script.sh")
        print()
        print("Workflow 4: Multiple Files")
        print("  $ dextr encrypt -k key.dxk -i file1.pdf file2.docx photos/ -o archive.dxe")
        print("  (All files and directories archived into single encrypted file)")
        print()

    elif topic == "examples":
        print("╔══════════════════════════════════════════════════╗")
        print("║          dextr Command Examples                  ║")
        print("╚══════════════════════════════════════════════════╝")
        print()
        print("Generate Keys:")
        print("  dextr generate                    # Creates dextrkey.dxk")
        print("  dextr generate mykey.dxk          # Custom filename")
        print("  dextr generate backup.dxk --force # Overwrite existing")
        print()
        print("Encrypt:")
        print("  dextr encrypt -k key.dxk -i file.txt -o backup.dxe")
        print("  dextr encrypt -k key.dxk -i folder/ -o backup.dxe")
        print("  dextr encrypt -k key.dxk -i file1.txt file2.pdf -o backup.dxe")
        print("  dextr encrypt -k key.dxk -i data/ -o backup.dxe --quiet")
        print()
        print("Decrypt:")
        print("  dextr decrypt -k key.dxk -i backup.dxe -o restored/")
        print("  dextr decrypt -k key.dxk -i backup.dxe -o . --force")
        print("  dextr decrypt -k key.dxk -i backup.dxe -o output/ --verbose")
        print()
        print("Verify Archive:")
        print("  dextr verify -i backup.dxe        # Check structure without key")
        print()
        print("List Contents:")
        print("  dextr list -k key.dxk -i backup.dxe  # Show archive contents")
        print()
        print("Info:")
        print("  dextr info -k key.dxk            # View key metadata")
        print()
        print("Help:")
        print("  dextr help                        # This guide")
        print("  dextr help security               # Security information")
        print("  dextr help workflow               # Common workflows")
        print("  dextr --help                      # Command syntax")
        print()

    elif topic == "troubleshooting":
        print("╔══════════════════════════════════════════════════╗")
        print("║          dextr Troubleshooting Guide             ║")
        print("╚══════════════════════════════════════════════════╝")
        print()
        print("Problem: 'Key mismatch' error")
        print("  Solution: You're using the wrong key file")
        print("  → Use the same key that was used to encrypt the archive")
        print()
        print("Problem: 'Permission denied'")
        print("  Solution: Check file/directory permissions")
        print("  → Make sure you have read access to input files")
        print("  → Make sure you have write access to output directory")
        print()
        print("Problem: 'Output file already exists'")
        print("  Solution: File would be overwritten")
        print("  → Use --force flag to overwrite: dextr ... --force")
        print("  → Or choose a different output filename")
        print()
        print("Problem: 'Output directory not empty'")
        print("  Solution: Safety check to prevent mixing files")
        print("  → Use --force to extract anyway")
        print("  → Or choose an empty directory")
        print()
        print("Problem: Decryption fails with 'integrity check failed'")
        print("  Solution: Archive is corrupted or tampered")
        print("  → Archive file may be damaged")
        print("  → File transfer may have corrupted data")
        print("  → Try re-downloading or re-creating the archive")
        print()
        print("Problem: 'cryptography module not found'")
        print("  Solution: Dependencies not installed")
        print("  → Run: pip install --user -r requirements.txt")
        print("  → Or: pip install --user cryptography")
        print()

    else:
        # General help
        print("╔══════════════════════════════════════════════════╗")
        print(f"║              D E X T R  v{__version__}                   ║")
        print("║      Secure Archiving & Encryption System        ║")
        print("║            Created by orpheus497                 ║")
        print("╚══════════════════════════════════════════════════╝")
        print()
        print("COMMANDS:")
        print("  generate [path]              Generate a new encryption key")
        print("  encrypt -k KEY -i INPUT... -o OUTPUT")
        print("                               Encrypt files/directories")
        print("  decrypt -k KEY -i INPUT -o OUTPUT")
        print("                               Decrypt and extract archive")
        print("  verify -i ARCHIVE            Verify archive structure")
        print("  list -k KEY -i ARCHIVE       List archive contents")
        print("  info -k KEY                  Display key file information")
        print("  help [topic]                 Show detailed help")
        print()
        print("HELP TOPICS:")
        print("  dextr help                   This guide (general help)")
        print("  dextr help security          Security architecture & best practices")
        print("  dextr help workflow          Common usage workflows")
        print("  dextr help examples          Command examples")
        print("  dextr help troubleshooting   Common problems and solutions")
        print()
        print("QUICK START:")
        print("  1. dextr generate                    # Create key file")
        print("  2. dextr encrypt -k dextrkey.dxk -i files/ -o backup.dxe")
        print("  3. dextr decrypt -k dextrkey.dxk -i backup.dxe -o restored/")
        print()
        print("DOCUMENTATION:")
        print("  Full guide:        cat README.md (or type README.md on Windows)")
        print("  Quick reference:   cat USAGE.md")
        print("  Command syntax:    dextr --help")
        print()
        print("For command-specific help: dextr COMMAND --help")
        print("Example: dextr encrypt --help")
        print()

    return 0


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="dextr",
        description="Secure archiving and encryption system",
        epilog="Created by orpheus497. Use responsibly and always maintain key backups.",
    )

    parser.add_argument("--version", action="version", version=f"dextr {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate command
    parser_generate = subparsers.add_parser("generate", help="Generate a new encryption key file")
    parser_generate.add_argument(
        "output",
        nargs="?",
        default=None,
        help="Output path for the key file (default: dextrkey.dxk)",
    )
    parser_generate.add_argument(
        "--force", action="store_true", help="Overwrite existing key file if present"
    )
    parser_generate.add_argument(
        "--password", action="store_true", help="Encrypt the key file with a password"
    )
    parser_generate.add_argument("--password-file", metavar="FILE", help="Read password from file")

    # Encrypt command
    parser_encrypt = subparsers.add_parser(
        "encrypt", help="Encrypt files or directories into an archive"
    )
    parser_encrypt.add_argument("-k", "--key", required=True, help="Path to the key file (.dxk)")
    parser_encrypt.add_argument(
        "-i", "--input", required=True, nargs="+", help="Input file(s) or directory(ies) to encrypt"
    )
    parser_encrypt.add_argument(
        "-o", "--output", required=True, help="Output path for the encrypted archive (.dxe)"
    )
    parser_encrypt.add_argument(
        "--force", action="store_true", help="Overwrite existing output file if present"
    )
    parser_encrypt.add_argument("--quiet", action="store_true", help="Suppress status messages")
    parser_encrypt.add_argument(
        "--verbose", action="store_true", help="Show detailed progress information"
    )
    parser_encrypt.add_argument(
        "--password",
        action="store_true",
        help="Prompt for password if key file is password-protected",
    )
    parser_encrypt.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from file for password-protected keys",
    )

    # Decrypt command
    parser_decrypt = subparsers.add_parser(
        "decrypt", help="Decrypt and extract an encrypted archive"
    )
    parser_decrypt.add_argument("-k", "--key", required=True, help="Path to the key file (.dxk)")
    parser_decrypt.add_argument(
        "-i", "--input", required=True, help="Input encrypted archive file (.dxe)"
    )
    parser_decrypt.add_argument(
        "-o", "--output", required=True, help="Output directory for extracted files"
    )
    parser_decrypt.add_argument(
        "--force", action="store_true", help="Extract even if output directory is not empty"
    )
    parser_decrypt.add_argument("--quiet", action="store_true", help="Suppress status messages")
    parser_decrypt.add_argument(
        "--verbose", action="store_true", help="Show detailed progress information"
    )
    parser_decrypt.add_argument(
        "--password",
        action="store_true",
        help="Prompt for password if key file is password-protected",
    )
    parser_decrypt.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from file for password-protected keys",
    )

    # Info command
    parser_info = subparsers.add_parser("info", help="Display information about a key file")
    parser_info.add_argument("-k", "--key", required=True, help="Path to the key file (.dxk)")
    parser_info.add_argument(
        "--password",
        action="store_true",
        help="Prompt for password if key file is password-protected",
    )
    parser_info.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from file for password-protected keys",
    )

    # Verify command (new feature)
    parser_verify = subparsers.add_parser(
        "verify", help="Verify archive structure without decrypting"
    )
    parser_verify.add_argument(
        "-i", "--input", required=True, help="Path to the archive file (.dxe)"
    )

    # List command (new feature)
    parser_list = subparsers.add_parser("list", help="List archive contents without extracting")
    parser_list.add_argument("-k", "--key", required=True, help="Path to the key file (.dxk)")
    parser_list.add_argument("-i", "--input", required=True, help="Path to the archive file (.dxe)")
    parser_list.add_argument("--quiet", action="store_true", help="Suppress status messages")
    parser_list.add_argument(
        "--password",
        action="store_true",
        help="Prompt for password if key file is password-protected",
    )
    parser_list.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from file for password-protected keys",
    )

    # Check command (new feature)
    parser_check = subparsers.add_parser("check", help="Check archive integrity with key")
    parser_check.add_argument("-k", "--key", required=True, help="Path to the key file (.dxk)")
    parser_check.add_argument(
        "-i", "--input", required=True, help="Path to the archive file (.dxe)"
    )
    parser_check.add_argument(
        "--quick", action="store_true", help="Perform quick check (first layer only)"
    )
    parser_check.add_argument("--quiet", action="store_true", help="Suppress status messages")
    parser_check.add_argument(
        "--verbose", action="store_true", help="Show detailed progress information"
    )
    parser_check.add_argument(
        "--password",
        action="store_true",
        help="Prompt for password if key file is password-protected",
    )
    parser_check.add_argument(
        "--password-file",
        metavar="FILE",
        help="Read password from file for password-protected keys",
    )

    # Help command
    parser_help = subparsers.add_parser("help", help="Show detailed usage guide and examples")
    parser_help.add_argument(
        "topic",
        nargs="?",
        choices=["security", "workflow", "examples", "troubleshooting"],
        help="Specific help topic (security, workflow, examples, troubleshooting)",
    )

    # Parse arguments
    args = parser.parse_args()

    # Load configuration
    config = load_config()

    # Setup logging
    setup_logging(
        log_level=config.get("log_level", "INFO"),
        log_file=config.get("log_file", None),
        verbose=getattr(args, "verbose", False),
        quiet=getattr(args, "quiet", False),
    )

    # If no command specified, show help
    if not args.command:
        parser.print_help()
        return 1

    # Route to appropriate command handler
    if args.command == "generate":
        return cmd_generate(args)
    elif args.command == "encrypt":
        return cmd_encrypt(args, config)
    elif args.command == "decrypt":
        return cmd_decrypt(args)
    elif args.command == "info":
        return cmd_info(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "list":
        return cmd_list(args)
    elif args.command == "check":
        return cmd_check(args)
    elif args.command == "help":
        return cmd_help(args)
    else:
        error_exit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
