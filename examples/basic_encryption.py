#!/usr/bin/env python3
"""
Basic Encryption Example

Demonstrates basic dextr usage:
- Generate encryption key
- Encrypt files
- Decrypt archive
- Check integrity
"""

import os
import tempfile
from pathlib import Path

from dextr import (
    check_archive_integrity,
    decrypt_archive,
    encrypt_paths,
    generate_key_file,
    load_key_file,
)


def main():
    print("=== Dextr Basic Encryption Example ===\n")

    # Create temporary directory for demo
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # 1. Generate encryption key
        print("1. Generating encryption key...")
        key_path = temp_path / "demo.dxk"
        metadata = generate_key_file(str(key_path))
        print(f"   ✓ Key generated: {key_path}")
        print(f"   ✓ Key ID: {metadata['key_id'][:16]}...")

        # 2. Create sample files to encrypt
        print("\n2. Creating sample files...")
        sample_dir = temp_path / "sample_files"
        sample_dir.mkdir()

        (sample_dir / "document.txt").write_text("Confidential document content")
        (sample_dir / "data.json").write_text('{"secret": "value"}')

        subdir = sample_dir / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("Nested file content")

        print(f"   ✓ Created 3 files in {sample_dir}")

        # 3. Load key and encrypt
        print("\n3. Encrypting files...")
        master_key, _ = load_key_file(str(key_path))

        archive_path = temp_path / "encrypted.dxe"
        encrypt_paths([str(sample_dir)], str(archive_path), master_key)

        archive_size = os.path.getsize(archive_path)
        print(f"   ✓ Archive created: {archive_path}")
        print(f"   ✓ Archive size: {archive_size:,} bytes")

        # 4. Check archive integrity
        print("\n4. Checking archive integrity...")
        result = check_archive_integrity(str(archive_path), master_key, quick=True)

        if result["valid"]:
            print("   ✓ Archive integrity: VALID")
            print(f"   ✓ Encryption layers: {result['layers_validated']}")
        else:
            print("   ✗ Archive integrity: INVALID")

        # 5. Decrypt archive
        print("\n5. Decrypting archive...")
        output_dir = temp_path / "decrypted"
        decrypt_archive(str(archive_path), str(output_dir), master_key)

        # Count restored files
        restored_files = list(output_dir.rglob("*"))
        restored_count = sum(1 for f in restored_files if f.is_file())

        print(f"   ✓ Files restored: {restored_count}")
        print(f"   ✓ Output directory: {output_dir}")

        # 6. Verify content
        print("\n6. Verifying restored content...")
        restored_doc = output_dir / "sample_files" / "document.txt"
        if restored_doc.exists():
            content = restored_doc.read_text()
            if content == "Confidential document content":
                print("   ✓ Content verified: Matches original")
            else:
                print("   ✗ Content mismatch")
        else:
            print("   ✗ File not found")

    print("\n=== Example completed successfully! ===")


if __name__ == "__main__":
    main()
