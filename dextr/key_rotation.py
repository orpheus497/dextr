"""
dextr/key_rotation.py

Key rotation utilities for the dextr application.
Provides functions for rotating encryption keys on archives and batch key rotation.

Security Note: Key rotation is an important security practice. Keys should be
rotated periodically or immediately if there's any suspicion of compromise.

Original Concept by orpheus497
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from dextr.archive_utils import rekey_archive
from dextr.core import check_archive_integrity, load_key_file
from dextr.exceptions import (
    DecryptionError,
    DextrError,
    EncryptionError,
    KeyManagementError,
    ValidationError,
)
from dextr.logging_config import (
    get_logger,
    log_operation_complete,
    log_operation_error,
    log_operation_start,
    log_security_event,
)
from dextr.validation import validate_archive_file, validate_key_file

logger = get_logger(__name__)


def rotate_archive_key(
    archive_path: str,
    old_key_path: str,
    new_key_path: str,
    output_path: Optional[str] = None,
    verify: bool = True,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    old_key_password: Optional[str] = None,
    new_key_password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Rotate the encryption key for an archive.

    Re-encrypts an archive with a new encryption key. Can either create a new
    archive or replace the original (with backup).

    Args:
        archive_path: Path to encrypted archive
        old_key_path: Path to current decryption key file
        new_key_path: Path to new encryption key file
        output_path: Path for output archive (None to replace original)
        verify: If True, verify the new archive after rotation
        progress_callback: Optional callback for progress tracking
        old_key_password: Password for old key file (if password-protected)
        new_key_password: Password for new key file (if password-protected)

    Returns:
        Dictionary with rotation results:
        - success: Boolean indicating success
        - output_archive: Path to output archive
        - verification_passed: Boolean (if verify=True)
        - original_backed_up: Boolean indicating if original was backed up
        - backup_path: Path to backup (if applicable)

    Raises:
        KeyManagementError: If key loading fails
        DecryptionError: If archive decryption fails
        EncryptionError: If re-encryption fails
        ValidationError: If input validation fails
    """
    log_operation_start(
        "rotate_archive_key",
        archive=archive_path,
        old_key=old_key_path,
        new_key=new_key_path,
    )

    try:
        # Validate inputs
        archive = validate_archive_file(archive_path, for_output=False)
        old_key_file = validate_key_file(old_key_path)
        new_key_file = validate_key_file(new_key_path)

        # Load keys
        if progress_callback:
            progress_callback("Loading keys", 0, 100)

        logger.info("Loading old decryption key")
        old_key, old_metadata = load_key_file(str(old_key_file), password=old_key_password)

        logger.info("Loading new encryption key")
        new_key, new_metadata = load_key_file(str(new_key_file), password=new_key_password)

        # Determine output path
        if output_path is None:
            # Replace original - create backup first
            backup_path = str(archive) + ".backup_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_archive = str(archive) + ".tmp"
            will_replace = True
        else:
            backup_path = None
            output_archive = output_path
            will_replace = False

        # Perform key rotation (re-encryption)
        if progress_callback:
            progress_callback("Re-encrypting archive", 10, 100)

        logger.info(f"Rotating key for {archive}")
        log_security_event(
            "key_rotation_started",
            {
                "archive": str(archive),
                "old_key_id": old_metadata.get("key_id", "unknown"),
                "new_key_id": new_metadata.get("key_id", "unknown"),
            },
            level="INFO",
        )

        rekey_archive(
            str(archive),
            output_archive,
            old_key,
            new_key,
            progress_callback=None,
        )

        # Verify new archive if requested
        verification_passed = False
        if verify:
            if progress_callback:
                progress_callback("Verifying new archive", 70, 100)

            logger.info("Verifying re-encrypted archive")
            result = check_archive_integrity(output_archive, new_key, quick=False)

            if not result["valid"]:
                error_msg = result.get("error", "Unknown verification error")
                raise DecryptionError(f"Archive verification failed: {error_msg}")

            verification_passed = True
            logger.info("Archive verification passed")

        # Handle original file replacement
        backed_up = False
        if will_replace:
            if progress_callback:
                progress_callback("Replacing original", 90, 100)

            # Create backup
            import shutil

            shutil.copy2(archive, backup_path)
            backed_up = True
            logger.info(f"Created backup at {backup_path}")

            # Replace original
            os.replace(output_archive, archive)
            output_archive = str(archive)
            logger.info("Original archive replaced with re-encrypted version")

        if progress_callback:
            progress_callback("Complete", 100, 100)

        result = {
            "success": True,
            "output_archive": output_archive,
            "verification_passed": verification_passed,
            "original_backed_up": backed_up,
            "backup_path": backup_path,
        }

        log_security_event(
            "key_rotation_completed",
            {
                "archive": output_archive,
                "new_key_id": new_metadata.get("key_id", "unknown"),
                "verified": verification_passed,
            },
            level="INFO",
        )

        log_operation_complete(
            "rotate_archive_key",
            output=output_archive,
            verified=verification_passed,
        )

        return result

    except (KeyManagementError, DecryptionError, EncryptionError, ValidationError):
        raise
    except Exception as e:
        log_operation_error("rotate_archive_key", e, archive=archive_path)
        raise DextrError(f"Key rotation failed: {e}") from e


def batch_rotate_keys(
    archives: List[str],
    old_key_path: str,
    new_key_path: str,
    in_place: bool = True,
    verify: bool = True,
    stop_on_error: bool = False,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
    old_key_password: Optional[str] = None,
    new_key_password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Rotate keys for multiple archives in batch.

    Args:
        archives: List of archive paths
        old_key_path: Path to current decryption key file
        new_key_path: Path to new encryption key file
        in_place: If True, replace original archives (with backups)
        verify: If True, verify each archive after rotation
        stop_on_error: If True, stop batch on first error
        progress_callback: Optional callback(stage, current, total, archive_name)
        old_key_password: Password for old key file (if password-protected)
        new_key_password: Password for new key file (if password-protected)

    Returns:
        Dictionary with batch results:
        - total: Total number of archives
        - successful: Number of successful rotations
        - failed: Number of failed rotations
        - results: List of per-archive results
        - errors: Dictionary of errors (archive_path -> error_message)

    Raises:
        KeyManagementError: If key loading fails
        ValidationError: If input validation fails
    """
    log_operation_start(
        "batch_rotate_keys",
        num_archives=len(archives),
        old_key=old_key_path,
        new_key=new_key_path,
    )

    try:
        # Validate inputs
        if not archives:
            raise ValidationError("No archives provided for batch rotation")

        validate_key_file(old_key_path)
        validate_key_file(new_key_path)

        # Load keys once (reuse for all archives)
        logger.info("Loading keys for batch rotation")
        old_key, old_metadata = load_key_file(old_key_path, password=old_key_password)
        new_key, new_metadata = load_key_file(new_key_path, password=new_key_password)

        results = []
        errors = {}
        successful = 0
        failed = 0

        for i, archive_path in enumerate(archives):
            if progress_callback:
                progress_callback(
                    "Rotating keys",
                    i,
                    len(archives),
                    os.path.basename(archive_path),
                )

            try:
                # Determine output path
                if in_place:
                    output_path = None
                else:
                    base_name = os.path.splitext(archive_path)[0]
                    output_path = f"{base_name}_rekeyed.dxe"

                # Rotate key for this archive
                logger.info(f"Rotating key for archive {i+1}/{len(archives)}: {archive_path}")

                result = rotate_archive_key(
                    archive_path,
                    old_key_path,
                    new_key_path,
                    output_path=output_path,
                    verify=verify,
                    progress_callback=None,
                    old_key_password=old_key_password,
                    new_key_password=new_key_password,
                )

                results.append(
                    {
                        "archive": archive_path,
                        "output": result["output_archive"],
                        "success": True,
                        "verified": result["verification_passed"],
                        "backed_up": result["original_backed_up"],
                    }
                )

                successful += 1
                logger.info(f"Successfully rotated key for {archive_path}")

            except Exception as e:
                error_msg = str(e)
                results.append(
                    {
                        "archive": archive_path,
                        "success": False,
                        "error": error_msg,
                    }
                )

                errors[archive_path] = error_msg
                failed += 1
                logger.error(f"Failed to rotate key for {archive_path}: {error_msg}")

                if stop_on_error:
                    logger.warning("Stopping batch rotation due to error")
                    break

        if progress_callback:
            progress_callback("Complete", len(archives), len(archives), "")

        batch_result = {
            "total": len(archives),
            "successful": successful,
            "failed": failed,
            "results": results,
            "errors": errors,
        }

        log_security_event(
            "batch_key_rotation_completed",
            {
                "total": len(archives),
                "successful": successful,
                "failed": failed,
            },
            level="INFO",
        )

        log_operation_complete(
            "batch_rotate_keys",
            total=len(archives),
            successful=successful,
            failed=failed,
        )

        return batch_result

    except (KeyManagementError, ValidationError):
        raise
    except Exception as e:
        log_operation_error("batch_rotate_keys", e)
        raise DextrError(f"Batch key rotation failed: {e}") from e


def verify_rotation(
    archive_path: str,
    new_key_path: str,
    quick: bool = False,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify that an archive has been successfully rotated to a new key.

    Args:
        archive_path: Path to rotated archive
        new_key_path: Path to new key file
        quick: If True, perform quick verification (first layer only)
        password: Password for key file (if password-protected)

    Returns:
        Dictionary with verification results (see check_archive_integrity)

    Raises:
        KeyManagementError: If key loading fails
        DecryptionError: If verification fails
        ValidationError: If input validation fails
    """
    log_operation_start("verify_rotation", archive=archive_path, key=new_key_path)

    try:
        # Validate inputs
        validate_archive_file(archive_path, for_output=False)
        validate_key_file(new_key_path)

        # Load new key
        new_key, new_metadata = load_key_file(new_key_path, password=password)

        # Verify archive
        logger.info(f"Verifying rotated archive: {archive_path}")
        result = check_archive_integrity(archive_path, new_key, quick=quick)

        if result["valid"]:
            logger.info("Rotation verification successful")
        else:
            error_msg = result.get("error", "Unknown error")
            logger.error(f"Rotation verification failed: {error_msg}")

        log_operation_complete(
            "verify_rotation",
            archive=archive_path,
            valid=result["valid"],
        )

        return result

    except (KeyManagementError, DecryptionError, ValidationError):
        raise
    except Exception as e:
        log_operation_error("verify_rotation", e, archive=archive_path)
        raise DextrError(f"Rotation verification failed: {e}") from e


def create_rotation_report(
    batch_result: Dict[str, Any], output_file: Optional[str] = None
) -> str:
    """
    Create a human-readable report of batch key rotation results.

    Args:
        batch_result: Result dictionary from batch_rotate_keys()
        output_file: Optional file path to write report (None for string return)

    Returns:
        Report string

    Raises:
        IOError: If output file cannot be written
    """
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("BATCH KEY ROTATION REPORT")
    report_lines.append("=" * 70)
    report_lines.append("")
    report_lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    report_lines.append("")
    report_lines.append("SUMMARY:")
    report_lines.append(f"  Total Archives: {batch_result['total']}")
    report_lines.append(f"  Successful: {batch_result['successful']}")
    report_lines.append(f"  Failed: {batch_result['failed']}")
    report_lines.append("")

    if batch_result["successful"] > 0:
        report_lines.append("SUCCESSFUL ROTATIONS:")
        report_lines.append("-" * 70)
        for result in batch_result["results"]:
            if result["success"]:
                report_lines.append(f"  ✓ {result['archive']}")
                report_lines.append(f"    Output: {result['output']}")
                if result.get("verified"):
                    report_lines.append("    Verification: PASSED")
                if result.get("backed_up"):
                    report_lines.append("    Original: BACKED UP")
                report_lines.append("")

    if batch_result["failed"] > 0:
        report_lines.append("FAILED ROTATIONS:")
        report_lines.append("-" * 70)
        for result in batch_result["results"]:
            if not result["success"]:
                report_lines.append(f"  ✗ {result['archive']}")
                report_lines.append(f"    Error: {result.get('error', 'Unknown error')}")
                report_lines.append("")

    report_lines.append("=" * 70)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 70)

    report = "\n".join(report_lines)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)
            logger.info(f"Rotation report written to {output_file}")
        except IOError as e:
            raise IOError(f"Failed to write report file: {e}") from e

    return report
