"""
dextr/archive_utils.py

Archive manipulation utilities for the dextr application.
Provides functions for comparing, merging, and re-encrypting encrypted archives.

Original Concept by orpheus497
"""

import hashlib
import os
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from dextr.core import (
    decrypt_archive,
    encrypt_paths,
    get_archive_info,
    load_key_file,
)
from dextr.exceptions import (
    ArchivingError,
    DecryptionError,
    DextrError,
    EncryptionError,
    ValidationError,
)
from dextr.logging_config import (
    get_logger,
    log_operation_complete,
    log_operation_error,
    log_operation_start,
)
from dextr.validation import validate_archive_file, validate_input_paths, validate_path

logger = get_logger(__name__)


def compare_archives(
    archive1_path: str,
    archive2_path: str,
    key1: bytes,
    key2: Optional[bytes] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, Any]:
    """
    Compare the contents of two encrypted archives.

    Decrypts both archives to temporary directories and compares their contents,
    including file names, sizes, and content hashes.

    Args:
        archive1_path: Path to first encrypted archive
        archive2_path: Path to second encrypted archive
        key1: Decryption key for first archive
        key2: Decryption key for second archive (uses key1 if None)
        progress_callback: Optional callback for progress tracking

    Returns:
        Dictionary with comparison results:
        - identical: Boolean indicating if archives are identical
        - files_only_in_1: List of files only in archive 1
        - files_only_in_2: List of files only in archive 2
        - files_different: List of files that differ between archives
        - files_identical: List of files that are identical
        - total_files_1: Total file count in archive 1
        - total_files_2: Total file count in archive 2

    Raises:
        DecryptionError: If archive decryption fails
        ValidationError: If input validation fails
    """
    log_operation_start(
        "compare_archives", archive1=archive1_path, archive2=archive2_path
    )

    if key2 is None:
        key2 = key1

    temp_dir1 = None
    temp_dir2 = None

    try:
        # Validate inputs
        arch1 = validate_archive_file(archive1_path, for_output=False)
        arch2 = validate_archive_file(archive2_path, for_output=False)

        # Create temporary directories for extraction
        temp_dir1 = tempfile.mkdtemp(prefix="dextr_cmp1_")
        temp_dir2 = tempfile.mkdtemp(prefix="dextr_cmp2_")

        logger.info(f"Comparing {arch1} and {arch2}")

        # Decrypt both archives
        if progress_callback:
            progress_callback("Decrypting first archive", 0, 100)

        decrypt_archive(archive1_path, temp_dir1, key1)

        if progress_callback:
            progress_callback("Decrypting second archive", 40, 100)

        decrypt_archive(archive2_path, temp_dir2, key2)

        if progress_callback:
            progress_callback("Comparing contents", 80, 100)

        # Get file sets from both archives
        files1 = _get_file_set(Path(temp_dir1))
        files2 = _get_file_set(Path(temp_dir2))

        # Find differences
        only_in_1 = files1.keys() - files2.keys()
        only_in_2 = files2.keys() - files1.keys()
        common_files = files1.keys() & files2.keys()

        # Compare common files
        identical_files = []
        different_files = []

        for file_path in common_files:
            if _files_are_identical(files1[file_path], files2[file_path]):
                identical_files.append(file_path)
            else:
                different_files.append(file_path)

        result = {
            "identical": len(only_in_1) == 0
            and len(only_in_2) == 0
            and len(different_files) == 0,
            "files_only_in_1": sorted(list(only_in_1)),
            "files_only_in_2": sorted(list(only_in_2)),
            "files_different": sorted(different_files),
            "files_identical": sorted(identical_files),
            "total_files_1": len(files1),
            "total_files_2": len(files2),
        }

        if progress_callback:
            progress_callback("Complete", 100, 100)

        log_operation_complete(
            "compare_archives",
            identical=result["identical"],
            differences=len(only_in_1) + len(only_in_2) + len(different_files),
        )

        return result

    except (DecryptionError, ValidationError):
        raise
    except Exception as e:
        log_operation_error("compare_archives", e)
        raise DextrError(f"Archive comparison failed: {e}") from e

    finally:
        # Clean up temporary directories
        if temp_dir1:
            try:
                import shutil

                shutil.rmtree(temp_dir1)
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory: {e}")

        if temp_dir2:
            try:
                import shutil

                shutil.rmtree(temp_dir2)
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory: {e}")


def merge_archives(
    input_archives: List[str],
    output_archive: str,
    input_key: bytes,
    output_key: Optional[bytes] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> None:
    """
    Merge multiple encrypted archives into a single archive.

    Decrypts all input archives, combines their contents, and creates a new
    encrypted archive. Duplicate files are handled by keeping the version from
    the first archive containing the file.

    Args:
        input_archives: List of paths to input encrypted archives
        output_archive: Path for output encrypted archive
        input_key: Decryption key for input archives
        output_key: Encryption key for output archive (uses input_key if None)
        progress_callback: Optional callback for progress tracking

    Raises:
        DecryptionError: If archive decryption fails
        EncryptionError: If output archive creation fails
        ValidationError: If input validation fails
    """
    log_operation_start(
        "merge_archives",
        num_inputs=len(input_archives),
        output=output_archive,
    )

    if output_key is None:
        output_key = input_key

    temp_dir = None

    try:
        # Validate inputs
        if not input_archives:
            raise ValidationError("No input archives provided")

        for archive in input_archives:
            validate_archive_file(archive, for_output=False)

        validate_archive_file(output_archive, for_output=True)

        # Create temporary directory for merged content
        temp_dir = tempfile.mkdtemp(prefix="dextr_merge_")

        logger.info(f"Merging {len(input_archives)} archives into {output_archive}")

        # Track processed files to avoid duplicates
        processed_files: Set[str] = set()

        # Decrypt and merge each archive
        for i, archive_path in enumerate(input_archives):
            if progress_callback:
                progress = int((i / len(input_archives)) * 70)
                progress_callback(
                    f"Processing archive {i+1}/{len(input_archives)}", progress, 100
                )

            # Create temporary extraction directory
            extract_dir = tempfile.mkdtemp(prefix="dextr_extract_", dir=temp_dir)

            # Decrypt archive
            decrypt_archive(archive_path, extract_dir, input_key)

            # Copy files to merged directory
            for item in Path(extract_dir).rglob("*"):
                if item.is_file():
                    rel_path = item.relative_to(extract_dir)
                    rel_path_str = str(rel_path)

                    # Skip if already processed (keep first occurrence)
                    if rel_path_str in processed_files:
                        logger.debug(f"Skipping duplicate file: {rel_path_str}")
                        continue

                    # Copy file to merge directory
                    dest_path = Path(temp_dir) / rel_path
                    dest_path.parent.mkdir(parents=True, exist_ok=True)

                    import shutil

                    shutil.copy2(item, dest_path)
                    processed_files.add(rel_path_str)
                    logger.debug(f"Merged file: {rel_path_str}")

            # Remove extraction directory
            import shutil

            shutil.rmtree(extract_dir)

        # Encrypt merged content
        if progress_callback:
            progress_callback("Creating merged archive", 70, 100)

        # Get all top-level items in merge directory
        merge_items = [
            str(item) for item in Path(temp_dir).iterdir() if not item.name.startswith(".")
        ]

        if not merge_items:
            raise ArchivingError("No files to merge - all archives were empty")

        encrypt_paths(merge_items, output_archive, output_key, progress_callback=None)

        if progress_callback:
            progress_callback("Complete", 100, 100)

        log_operation_complete(
            "merge_archives",
            num_files_merged=len(processed_files),
            output=output_archive,
        )

    except (DecryptionError, EncryptionError, ValidationError, ArchivingError):
        raise
    except Exception as e:
        log_operation_error("merge_archives", e)
        raise DextrError(f"Archive merge failed: {e}") from e

    finally:
        # Clean up temporary directory
        if temp_dir:
            try:
                import shutil

                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory: {e}")


def rekey_archive(
    input_archive: str,
    output_archive: str,
    old_key: bytes,
    new_key: bytes,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> None:
    """
    Re-encrypt an archive with a different encryption key.

    Decrypts the input archive with the old key and re-encrypts with the new key.
    This is useful for key rotation or when an encryption key has been compromised.

    Args:
        input_archive: Path to input encrypted archive
        output_archive: Path for output encrypted archive
        old_key: Decryption key for input archive
        new_key: Encryption key for output archive
        progress_callback: Optional callback for progress tracking

    Raises:
        DecryptionError: If archive decryption fails
        EncryptionError: If output archive creation fails
        ValidationError: If input validation fails
    """
    log_operation_start(
        "rekey_archive",
        input=input_archive,
        output=output_archive,
    )

    temp_dir = None

    try:
        # Validate inputs
        validate_archive_file(input_archive, for_output=False)
        validate_archive_file(output_archive, for_output=True)

        # Create temporary directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="dextr_rekey_")

        logger.info(f"Re-keying {input_archive} to {output_archive}")

        # Decrypt with old key
        if progress_callback:
            progress_callback("Decrypting with old key", 0, 100)

        decrypt_archive(input_archive, temp_dir, old_key, progress_callback=None)

        # Re-encrypt with new key
        if progress_callback:
            progress_callback("Encrypting with new key", 50, 100)

        # Get all items in temp directory
        temp_items = [
            str(item) for item in Path(temp_dir).iterdir() if not item.name.startswith(".")
        ]

        encrypt_paths(temp_items, output_archive, new_key, progress_callback=None)

        if progress_callback:
            progress_callback("Complete", 100, 100)

        log_operation_complete("rekey_archive", output=output_archive)

    except (DecryptionError, EncryptionError, ValidationError):
        raise
    except Exception as e:
        log_operation_error("rekey_archive", e)
        raise DextrError(f"Archive re-keying failed: {e}") from e

    finally:
        # Clean up temporary directory
        if temp_dir:
            try:
                import shutil

                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory: {e}")


def get_archive_file_list(
    archive_path: str, key: bytes
) -> List[Dict[str, Any]]:
    """
    Get a list of files in an encrypted archive without full extraction.

    Decrypts the archive to a temporary location and catalogs all files.

    Args:
        archive_path: Path to encrypted archive
        key: Decryption key

    Returns:
        List of dictionaries containing file information:
        - path: Relative path of file
        - size: File size in bytes
        - is_dir: Boolean indicating if item is a directory

    Raises:
        DecryptionError: If archive decryption fails
        ValidationError: If input validation fails
    """
    temp_dir = None

    try:
        # Validate input
        validate_archive_file(archive_path, for_output=False)

        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix="dextr_list_")

        # Decrypt archive
        decrypt_archive(archive_path, temp_dir, key)

        # Catalog files
        file_list = []
        for item in sorted(Path(temp_dir).rglob("*")):
            if item == Path(temp_dir):
                continue

            rel_path = item.relative_to(temp_dir)
            file_info = {
                "path": str(rel_path),
                "size": item.stat().st_size if item.is_file() else 0,
                "is_dir": item.is_dir(),
            }
            file_list.append(file_info)

        return file_list

    finally:
        # Clean up temporary directory
        if temp_dir:
            try:
                import shutil

                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory: {e}")


# Helper functions


def _get_file_set(directory: Path) -> Dict[str, Dict[str, Any]]:
    """
    Get a set of files with their metadata from a directory.

    Args:
        directory: Directory to scan

    Returns:
        Dictionary mapping relative paths to file metadata
    """
    files = {}
    for item in directory.rglob("*"):
        if item.is_file():
            rel_path = str(item.relative_to(directory))
            files[rel_path] = {
                "path": item,
                "size": item.stat().st_size,
                "hash": _calculate_file_hash(item),
            }
    return files


def _calculate_file_hash(file_path: Path) -> str:
    """
    Calculate SHA-256 hash of a file.

    Args:
        file_path: Path to file

    Returns:
        Hexadecimal hash string
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):  # 64KB chunks
            hasher.update(chunk)
    return hasher.hexdigest()


def _files_are_identical(file1_info: Dict[str, Any], file2_info: Dict[str, Any]) -> bool:
    """
    Check if two files are identical based on size and content hash.

    Args:
        file1_info: Metadata dictionary for first file
        file2_info: Metadata dictionary for second file

    Returns:
        True if files are identical, False otherwise
    """
    return (
        file1_info["size"] == file2_info["size"] and file1_info["hash"] == file2_info["hash"]
    )
