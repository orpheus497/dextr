#!/usr/bin/env python3
"""
Progress Tracking Example

Demonstrates custom progress callbacks for integrating dextr
into larger applications with custom UI/logging.

Shows:
- Custom progress callback implementation
- Integration with different UI frameworks (console, logging)
- Real-time progress monitoring
- Detailed operation tracking
"""

import logging
import tempfile
from pathlib import Path
from typing import Optional

from dextr import generate_key_file, load_key_file, encrypt_paths, decrypt_archive


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProgressTracker:
    """Custom progress tracking class."""

    def __init__(self, name: str = "Operation", verbose: bool = True):
        self.name = name
        self.verbose = verbose
        self.total_bytes = 0
        self.processed_bytes = 0
        self.current_file = None
        self.file_count = 0
        self.completed_files = 0

    def update(self, current: int, total: int, filename: Optional[str] = None):
        """Update progress state."""
        self.processed_bytes = current
        self.total_bytes = total

        if filename and filename != self.current_file:
            self.current_file = filename
            self.completed_files += 1

        if self.verbose:
            percentage = (current / total * 100) if total > 0 else 0
            if filename:
                print(
                    f"{self.name}: {percentage:.1f}% - {filename} "
                    f"({current:,}/{total:,} bytes)"
                )
            else:
                print(
                    f"{self.name}: {percentage:.1f}% ({current:,}/{total:,} bytes)"
                )

    def complete(self):
        """Mark operation as complete."""
        if self.verbose:
            print(f"{self.name}: ✓ Complete ({self.total_bytes:,} bytes)")


class LoggingProgressTracker:
    """Progress tracker using Python logging."""

    def __init__(self, name: str = "Operation"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.last_percentage = 0

    def update(self, current: int, total: int, filename: Optional[str] = None):
        """Update progress with logging."""
        percentage = (current / total * 100) if total > 0 else 0

        # Log every 10% increment
        if int(percentage / 10) > int(self.last_percentage / 10):
            self.logger.info(
                f"Progress: {percentage:.0f}% ({current:,}/{total:,} bytes)"
            )

        if filename:
            self.logger.debug(f"Processing: {filename}")

        self.last_percentage = percentage

    def complete(self):
        """Mark operation as complete."""
        self.logger.info(f"{self.name} completed successfully")


class SilentProgressTracker:
    """Silent progress tracker that only tracks state."""

    def __init__(self):
        self.current_bytes = 0
        self.total_bytes = 0
        self.completed = False

    def update(self, current: int, total: int, filename: Optional[str] = None):
        """Update internal state only."""
        self.current_bytes = current
        self.total_bytes = total

    def complete(self):
        """Mark as complete."""
        self.completed = True

    def get_progress(self) -> dict:
        """Get current progress state."""
        return {
            "current": self.current_bytes,
            "total": self.total_bytes,
            "percentage": (
                (self.current_bytes / self.total_bytes * 100)
                if self.total_bytes > 0
                else 0
            ),
            "completed": self.completed,
        }


def create_test_data(base_path: Path) -> list:
    """Create sample files for testing."""
    files = []

    # Create files of varying sizes
    sizes = {
        "small.txt": "Small file content\n" * 10,
        "medium.txt": "Medium file content\n" * 100,
        "large.txt": "Large file content\n" * 1000,
    }

    for filename, content in sizes.items():
        file_path = base_path / filename
        file_path.write_text(content)
        files.append(str(file_path))

    return files


def demo_console_progress():
    """Demo 1: Console progress tracking."""
    print("\n=== Demo 1: Console Progress Tracking ===\n")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Setup
        key_path = temp_path / "demo.dxk"
        generate_key_file(str(key_path))
        master_key, _ = load_key_file(str(key_path))

        files = create_test_data(temp_path / "data")
        archive_path = temp_path / "archive.dxe"

        # Encrypt with console progress
        print("Encrypting with console progress:")
        tracker = ProgressTracker("Encryption", verbose=True)

        # Note: dextr uses tqdm for progress by default
        # This demo shows how you would implement custom tracking
        encrypt_paths(files, str(archive_path), master_key)
        tracker.complete()

        print("\nDecrypting with console progress:")
        output_dir = temp_path / "restored"
        tracker = ProgressTracker("Decryption", verbose=True)
        decrypt_archive(str(archive_path), str(output_dir), master_key)
        tracker.complete()


def demo_logging_progress():
    """Demo 2: Logging-based progress tracking."""
    print("\n=== Demo 2: Logging Progress Tracking ===\n")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Setup
        key_path = temp_path / "demo.dxk"
        generate_key_file(str(key_path))
        master_key, _ = load_key_file(str(key_path))

        files = create_test_data(temp_path / "data")
        archive_path = temp_path / "archive.dxe"

        # Encrypt with logging progress
        logger.info("Starting encryption with logging progress")
        tracker = LoggingProgressTracker("Encryption")

        encrypt_paths(files, str(archive_path), master_key)
        tracker.complete()

        logger.info("Starting decryption with logging progress")
        output_dir = temp_path / "restored"
        tracker = LoggingProgressTracker("Decryption")
        decrypt_archive(str(archive_path), str(output_dir), master_key)
        tracker.complete()


def demo_silent_progress():
    """Demo 3: Silent progress tracking (for polling)."""
    print("\n=== Demo 3: Silent Progress Tracking ===\n")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Setup
        key_path = temp_path / "demo.dxk"
        generate_key_file(str(key_path))
        master_key, _ = load_key_file(str(key_path))

        files = create_test_data(temp_path / "data")
        archive_path = temp_path / "archive.dxe"

        # Encrypt with silent tracking
        print("Encrypting (silent tracking)...")
        tracker = SilentProgressTracker()
        encrypt_paths(files, str(archive_path), master_key)
        tracker.complete()

        # Get final state
        progress = tracker.get_progress()
        print(f"✓ Encryption completed: {progress['percentage']:.1f}%")
        print(f"  Total bytes: {progress['total']:,}")

        # Decrypt with silent tracking
        print("\nDecrypting (silent tracking)...")
        output_dir = temp_path / "restored"
        tracker = SilentProgressTracker()
        decrypt_archive(str(archive_path), str(output_dir), master_key)
        tracker.complete()

        progress = tracker.get_progress()
        print(f"✓ Decryption completed: {progress['percentage']:.1f}%")


def main():
    """Run all progress tracking demos."""
    print("=== Dextr Progress Tracking Examples ===")
    print("\nThese examples show different approaches to progress tracking")
    print("for integrating dextr into larger applications.\n")

    # Run demos
    demo_console_progress()
    demo_logging_progress()
    demo_silent_progress()

    # Summary
    print("\n" + "=" * 60)
    print("INTEGRATION TIPS")
    print("=" * 60)
    print("\n1. Console UI: Use ProgressTracker for terminal applications")
    print("2. Web/GUI: Use SilentProgressTracker with polling")
    print("3. Services: Use LoggingProgressTracker for background tasks")
    print("4. Custom: Implement your own tracker class")
    print("\nNote: dextr uses tqdm for built-in progress bars.")
    print("For custom integration, you can disable tqdm and implement")
    print("your own progress tracking as shown in these examples.")
    print("=" * 60)


if __name__ == "__main__":
    main()
