#!/usr/bin/env python3
"""
Automated Backup Script

Production-ready backup script with:
- Automatic archive naming with timestamps
- Configurable backup directory
- Password protection support
- Integrity verification
- Logging

Usage:
    python automated_backup.py /path/to/backup
    python automated_backup.py /path/to/backup --output /backups
    python automated_backup.py /path/to/backup --password
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from dextr import (
    check_archive_integrity,
    encrypt_paths,
    generate_key_file,
    load_key_file,
)
from dextr.key_protection import prompt_password

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Automated backup script using dextr encryption")
    parser.add_argument("paths", nargs="+", help="Paths to backup (files/directories)")
    parser.add_argument(
        "-o",
        "--output",
        help="Output directory for backups (default: ./backups)",
        default="./backups",
    )
    parser.add_argument(
        "-k",
        "--key",
        help="Encryption key file (default: generate new key)",
        default=None,
    )
    parser.add_argument("--password", action="store_true", help="Use password-protected key")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify archive integrity after creation",
    )
    parser.add_argument(
        "--prefix", help="Prefix for backup filename (default: backup)", default="backup"
    )
    parser.add_argument(
        "--keep-keys",
        type=int,
        help="Number of old key files to keep (default: 5)",
        default=5,
    )

    return parser.parse_args()


def setup_backup_directory(output_dir: str) -> Path:
    """Create backup directory if it doesn't exist."""
    backup_path = Path(output_dir)
    backup_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Backup directory: {backup_path.absolute()}")
    return backup_path


def generate_backup_name(prefix: str) -> str:
    """Generate backup filename with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}"


def get_or_create_key(backup_dir: Path, backup_name: str, key_file: str, use_password: bool):
    """Get existing key or create new one."""
    password = None

    if key_file:
        # Use existing key
        key_path = Path(key_file)
        if not key_path.exists():
            logger.error(f"Key file not found: {key_file}")
            sys.exit(1)

        logger.info(f"Using existing key: {key_path}")

        if use_password:
            password = prompt_password("Enter key password: ")

        master_key, metadata = load_key_file(str(key_path), password=password)
        return master_key, metadata, key_path
    else:
        # Generate new key
        key_path = backup_dir / f"{backup_name}.dxk"

        if use_password:
            password = prompt_password("Create key password: ", confirm=True)

        logger.info(f"Generating new encryption key: {key_path}")
        metadata = generate_key_file(str(key_path), password=password)
        master_key, _ = load_key_file(str(key_path), password=password)

        return master_key, metadata, key_path


def cleanup_old_keys(backup_dir: Path, keep_count: int):
    """Remove old key files, keeping only the most recent ones."""
    key_files = sorted(backup_dir.glob("*.dxk"), key=os.path.getmtime, reverse=True)

    if len(key_files) > keep_count:
        for old_key in key_files[keep_count:]:
            logger.info(f"Removing old key file: {old_key.name}")
            old_key.unlink()


def verify_paths(paths: list) -> list:
    """Verify all paths exist and are accessible."""
    valid_paths = []

    for path_str in paths:
        path = Path(path_str)
        if not path.exists():
            logger.warning(f"Path does not exist, skipping: {path_str}")
            continue
        valid_paths.append(path_str)

    return valid_paths


def main():
    """Main backup function."""
    args = parse_args()

    logger.info("=== Dextr Automated Backup ===")

    # Verify input paths
    valid_paths = verify_paths(args.paths)
    if not valid_paths:
        logger.error("No valid paths to backup")
        sys.exit(1)

    logger.info(f"Backing up {len(valid_paths)} path(s):")
    for path in valid_paths:
        logger.info(f"  - {path}")

    # Setup backup directory
    backup_dir = setup_backup_directory(args.output)

    # Generate backup name
    backup_name = generate_backup_name(args.prefix)
    archive_path = backup_dir / f"{backup_name}.dxe"

    # Get or create encryption key
    master_key, metadata, key_path = get_or_create_key(
        backup_dir, backup_name, args.key, args.password
    )
    logger.info(f"Key ID: {metadata['key_id'][:16]}...")

    # Perform encryption
    logger.info("Encrypting files...")
    try:
        encrypt_paths(valid_paths, str(archive_path), master_key)
        archive_size = os.path.getsize(archive_path)
        logger.info(f"✓ Backup created: {archive_path.name}")
        logger.info(f"✓ Archive size: {archive_size:,} bytes")
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        sys.exit(1)

    # Verify archive integrity if requested
    if args.verify:
        logger.info("Verifying archive integrity...")
        try:
            result = check_archive_integrity(str(archive_path), master_key, quick=False)
            if result["valid"]:
                logger.info("✓ Archive integrity verified")
                logger.info(f"✓ Header valid: {result['header_valid']}")
                logger.info(f"✓ Key match: {result['key_match']}")
                logger.info(f"✓ Full decrypt success: {result['full_decrypt_success']}")
            else:
                logger.error("✗ Archive integrity check failed")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Integrity check failed: {e}")
            sys.exit(1)

    # Cleanup old keys if new key was generated
    if not args.key:
        cleanup_old_keys(backup_dir, args.keep_keys)

    # Summary
    logger.info("=== Backup Summary ===")
    logger.info(f"Archive: {archive_path}")
    logger.info(f"Key: {key_path}")
    logger.info(f"Size: {archive_size:,} bytes")
    logger.info("✓ Backup completed successfully")

    # Security reminder
    if not args.password:
        logger.warning("⚠ Key file is not password-protected")
        logger.warning("  Store key file securely with proper permissions")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nBackup cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
