#!/usr/bin/env python3
"""
Secure File Transfer Example

Demonstrates secure file sharing workflow:
1. Sender encrypts files and exports key
2. Receiver imports key and decrypts files

Usage:
    # Sender side
    python secure_transfer.py send /path/to/files

    # Receiver side
    python secure_transfer.py receive archive.dxe
"""

import argparse
import json
import sys
from pathlib import Path

from dextr import (
    check_archive_integrity,
    decrypt_archive,
    encrypt_paths,
    generate_key_file,
    load_key_file,
)


def cmd_send(args):
    """Sender workflow: encrypt files and export key."""
    print("=== Secure Transfer - Sender ===\n")

    # Validate input paths
    paths = [Path(p) for p in args.paths]
    for path in paths:
        if not path.exists():
            print(f"Error: Path does not exist: {path}")
            sys.exit(1)

    # Generate temporary encryption key
    key_path = Path(args.key if args.key else "transfer_key.dxk")
    archive_path = Path(args.output if args.output else "secure_transfer.dxe")

    print(f"1. Generating encryption key: {key_path}")
    metadata = generate_key_file(str(key_path))
    master_key, _ = load_key_file(str(key_path))

    print(f"   ✓ Key ID: {metadata['key_id'][:16]}...")
    print(f"   ✓ Created: {metadata['created_at']}")

    # Encrypt files
    print(f"\n2. Encrypting files to: {archive_path}")
    path_strs = [str(p) for p in paths]
    encrypt_paths(path_strs, str(archive_path), master_key)

    import os

    archive_size = os.path.getsize(archive_path)
    print(f"   ✓ Archive created ({archive_size:,} bytes)")

    # Export key information (without actual key material)
    export_data = {
        "key_id": metadata["key_id"],
        "created": metadata["created_at"],
        "key_file": str(key_path),
        "archive_file": str(archive_path),
        "instructions": "Share the key file securely (encrypted email, secure messaging, etc.)",
    }

    export_path = Path("transfer_info.json")
    with open(export_path, "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"\n3. Transfer information exported to: {export_path}")

    # Instructions
    print("\n" + "=" * 60)
    print("NEXT STEPS:")
    print("=" * 60)
    print("\n1. Send the encrypted archive to receiver:")
    print(f"   {archive_path}")
    print("\n2. Send the encryption key through a SECURE channel:")
    print(f"   {key_path}")
    print("\n3. Recommended secure channels:")
    print("   - Encrypted messaging (Signal, Wire)")
    print("   - PGP/GPG encrypted email")
    print("   - Password-protected file sharing")
    print("   - In-person transfer (USB drive)")
    print("\n⚠ WARNING: Do NOT send key and archive through same channel!")
    print("=" * 60)


def cmd_receive(args):
    """Receiver workflow: import key and decrypt."""
    print("=== Secure Transfer - Receiver ===\n")

    # Validate archive exists
    archive_path = Path(args.archive)
    if not archive_path.exists():
        print(f"Error: Archive not found: {archive_path}")
        sys.exit(1)

    # Check for key file
    key_path = Path(args.key if args.key else "transfer_key.dxk")
    if not key_path.exists():
        print(f"Error: Key file not found: {key_path}")
        print("\nPlease obtain the key file from sender through a secure channel")
        sys.exit(1)

    print(f"1. Loading encryption key: {key_path}")
    try:
        master_key, metadata = load_key_file(str(key_path))
        print(f"   ✓ Key ID: {metadata['key_id'][:16]}...")
        print(f"   ✓ Created: {metadata['created_at']}")
    except Exception as e:
        print(f"   ✗ Failed to load key: {e}")
        sys.exit(1)

    # Verify archive integrity
    print(f"\n2. Verifying archive integrity: {archive_path}")
    try:
        result = check_archive_integrity(str(archive_path), master_key, quick=True)
        if result["valid"]:
            print("   ✓ Archive integrity verified")
        else:
            print("   ✗ Archive integrity check failed")
            print("   WARNING: Archive may be corrupted or tampered with")
            response = input("   Continue anyway? [y/N]: ")
            if response.lower() != "y":
                sys.exit(1)
    except Exception as e:
        print(f"   ✗ Integrity check failed: {e}")
        sys.exit(1)

    # Decrypt archive
    output_dir = Path(args.output if args.output else "received_files")
    print(f"\n3. Decrypting to: {output_dir}")

    try:
        decrypt_archive(str(archive_path), str(output_dir), master_key)
        print("   ✓ Decryption successful")

        # Count received files
        files = list(output_dir.rglob("*"))
        file_count = sum(1 for f in files if f.is_file())
        print(f"   ✓ Received {file_count} file(s)")

    except Exception as e:
        print(f"   ✗ Decryption failed: {e}")
        sys.exit(1)

    # Summary
    print("\n" + "=" * 60)
    print("TRANSFER COMPLETE")
    print("=" * 60)
    print(f"\nFiles decrypted to: {output_dir.absolute()}")
    print("\nSecurity recommendations:")
    print("1. Verify files are as expected")
    print("2. Securely delete the key file after extraction")
    print("3. Optionally delete the encrypted archive")
    print("=" * 60)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Secure file transfer using dextr encryption")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # Send command
    send_parser = subparsers.add_parser("send", help="Encrypt files for sending")
    send_parser.add_argument("paths", nargs="+", help="Files/directories to send")
    send_parser.add_argument("-o", "--output", help="Output archive path")
    send_parser.add_argument("-k", "--key", help="Key file path")

    # Receive command
    receive_parser = subparsers.add_parser("receive", help="Decrypt received files")
    receive_parser.add_argument("archive", help="Encrypted archive to decrypt")
    receive_parser.add_argument("-k", "--key", help="Key file path")
    receive_parser.add_argument("-o", "--output", help="Output directory")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "send":
        cmd_send(args)
    elif args.command == "receive":
        cmd_receive(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
