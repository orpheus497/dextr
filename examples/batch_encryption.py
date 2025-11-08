#!/usr/bin/env python3
"""
Batch Encryption Example

Demonstrates encrypting multiple files and directories in a single archive.
Useful for backup scenarios where you need to archive multiple locations.
"""

import os
import tempfile
from pathlib import Path

from dextr import (
    generate_key_file,
    load_key_file,
    encrypt_paths,
    decrypt_archive,
    get_archive_info,
)


def create_sample_structure(base_path: Path) -> list:
    """Create sample directory structure with multiple locations."""
    locations = []

    # Location 1: Documents
    docs = base_path / "documents"
    docs.mkdir()
    (docs / "report.txt").write_text("Annual report content")
    (docs / "presentation.txt").write_text("Presentation slides")
    locations.append(str(docs))

    # Location 2: Photos
    photos = base_path / "photos"
    photos.mkdir()
    vacation = photos / "vacation"
    vacation.mkdir()
    (vacation / "photo1.txt").write_text("Photo data 1")
    (vacation / "photo2.txt").write_text("Photo data 2")
    locations.append(str(photos))

    # Location 3: Individual important file
    config = base_path / "config.ini"
    config.write_text("[settings]\nkey=value")
    locations.append(str(config))

    # Location 4: Database backups
    backups = base_path / "backups"
    backups.mkdir()
    (backups / "database.sql").write_text("-- SQL dump")
    (backups / "metadata.json").write_text('{"version": "1.0"}')
    locations.append(str(backups))

    return locations


def main():
    print("=== Dextr Batch Encryption Example ===\n")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # 1. Generate encryption key
        print("1. Generating encryption key...")
        key_path = temp_path / "batch.dxk"
        generate_key_file(str(key_path))
        master_key, key_metadata = load_key_file(str(key_path))
        print(f"   ✓ Key ID: {key_metadata['key_id'][:16]}...")

        # 2. Create sample file structure
        print("\n2. Creating sample file structure...")
        sample_base = temp_path / "sample_data"
        sample_base.mkdir()

        locations = create_sample_structure(sample_base)
        print(f"   ✓ Created {len(locations)} locations to encrypt:")
        for loc in locations:
            rel_path = Path(loc).relative_to(sample_base)
            print(f"     - {rel_path}")

        # 3. Batch encrypt all locations
        print("\n3. Encrypting all locations into single archive...")
        archive_path = temp_path / "batch_archive.dxe"

        # Count total files
        total_files = sum(
            1 for loc in locations for _ in Path(loc).rglob("*") if Path(_).is_file()
        )

        encrypt_paths(locations, str(archive_path), master_key)

        archive_size = os.path.getsize(archive_path)
        print(f"   ✓ Encrypted {total_files} files")
        print(f"   ✓ Archive size: {archive_size:,} bytes")

        # 4. View archive information
        print("\n4. Archive information:")
        info = get_archive_info(str(archive_path))
        print(f"   - Created: {info['created']}")
        print(f"   - Encryption: {info['encryption_algorithm']}")
        print(f"   - Compression: {info['compression_algorithm']}")
        print(f"   - Layers: {info['encryption_layers']}")

        # 5. Decrypt to restore all locations
        print("\n5. Decrypting archive...")
        restore_path = temp_path / "restored"
        decrypt_archive(str(archive_path), str(restore_path), master_key)

        # Count restored files
        restored_files = list(restore_path.rglob("*"))
        restored_count = sum(1 for f in restored_files if f.is_file())
        print(f"   ✓ Restored {restored_count} files")

        # 6. Verify structure preservation
        print("\n6. Verifying structure preservation...")
        checks = [
            restore_path / "documents" / "report.txt",
            restore_path / "photos" / "vacation" / "photo1.txt",
            restore_path / "config.ini",
            restore_path / "backups" / "database.sql",
        ]

        all_exist = all(f.exists() for f in checks)
        if all_exist:
            print("   ✓ All directory structures preserved")
        else:
            print("   ✗ Some files missing")

    print("\n=== Batch encryption completed successfully! ===")
    print("\nTip: This pattern is ideal for backing up multiple directories")
    print("     or creating comprehensive project archives.")


if __name__ == "__main__":
    main()
