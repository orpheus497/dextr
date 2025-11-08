"""
dextr/validation.py

Input validation and path security utilities for the dextr application.
This module provides comprehensive validation to prevent security vulnerabilities
including path traversal attacks, symlink attacks, and resource exhaustion.
"""

import os
import stat
import tarfile
from pathlib import Path
from typing import Optional, Union, List

from dextr.exceptions import ValidationError


def validate_path(
    path: Union[str, Path],
    must_exist: bool = True,
    must_be_file: bool = False,
    must_be_dir: bool = False,
    allow_symlinks: bool = True,
    parent_must_exist: bool = False,
) -> Path:
    """
    Validate and sanitize a file system path.

    Args:
        path: The path to validate
        must_exist: If True, path must exist
        must_be_file: If True, path must be a regular file
        must_be_dir: If True, path must be a directory
        allow_symlinks: If True, allow symbolic links
        parent_must_exist: If True, parent directory must exist

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    if not path:
        raise ValidationError("Path cannot be empty")

    # Convert to Path object and resolve
    try:
        path_obj = Path(path)
    except (TypeError, ValueError) as e:
        raise ValidationError(f"Invalid path: {e}") from e

    # Check for null bytes (potential security issue)
    if "\0" in str(path):
        raise ValidationError("Path contains null bytes")

    # Resolve to absolute path
    try:
        abs_path = path_obj.absolute()
    except (OSError, RuntimeError) as e:
        raise ValidationError(f"Cannot resolve path: {e}") from e

    # Check if path exists
    if must_exist and not abs_path.exists():
        raise ValidationError(f"Path does not exist: {abs_path}")

    # Check if parent exists
    if parent_must_exist and not abs_path.parent.exists():
        raise ValidationError(f"Parent directory does not exist: {abs_path.parent}")

    # If path exists, perform additional checks
    if abs_path.exists():
        # Check for symlinks
        if not allow_symlinks and abs_path.is_symlink():
            raise ValidationError(f"Symbolic links are not allowed: {abs_path}")

        # Follow symlinks for type checking
        real_path = abs_path.resolve()

        # Check if it's a file when required
        if must_be_file and not real_path.is_file():
            raise ValidationError(f"Path is not a regular file: {abs_path}")

        # Check if it's a directory when required
        if must_be_dir and not real_path.is_dir():
            raise ValidationError(f"Path is not a directory: {abs_path}")

    return abs_path


def validate_key_file(path: Union[str, Path]) -> Path:
    """
    Validate a key file path.

    Args:
        path: Path to the key file

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    key_path = validate_path(
        path,
        must_exist=True,
        must_be_file=True,
        allow_symlinks=False,  # Don't allow symlinks for security
    )

    # Check file extension
    if not key_path.suffix == ".dxk":
        raise ValidationError(f"Key file must have .dxk extension: {key_path}")

    # Check file permissions (warn if too permissive on Unix)
    if hasattr(os, "stat"):
        try:
            file_stat = key_path.stat()
            # On Unix-like systems, warn if readable by group or others
            if hasattr(stat, "S_IRWXG") and hasattr(stat, "S_IRWXO"):
                mode = file_stat.st_mode
                if (mode & stat.S_IRWXG) or (mode & stat.S_IRWXO):
                    # This is a warning, not an error
                    import warnings

                    warnings.warn(
                        f"Key file has overly permissive permissions: {key_path}. "
                        "Consider running: chmod 600 " + str(key_path),
                        UserWarning,
                    )
        except OSError:
            pass  # Can't check permissions, continue anyway

    return key_path


def validate_archive_file(path: Union[str, Path], for_output: bool = False) -> Path:
    """
    Validate an encrypted archive file path.

    Args:
        path: Path to the archive file
        for_output: If True, validates for output (doesn't need to exist)

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    archive_path = validate_path(
        path,
        must_exist=not for_output,
        must_be_file=not for_output,
        allow_symlinks=False,
        parent_must_exist=for_output,
    )

    # Check file extension
    if not archive_path.suffix == ".dxe":
        raise ValidationError(f"Archive file must have .dxe extension: {archive_path}")

    return archive_path


def validate_output_path(
    path: Union[str, Path], is_dir: bool = False, allow_overwrite: bool = False
) -> Path:
    """
    Validate an output path for writing.

    Args:
        path: Path to validate
        is_dir: If True, path should be a directory
        allow_overwrite: If True, allow overwriting existing files/dirs

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    output_path = validate_path(
        path, must_exist=False, allow_symlinks=False, parent_must_exist=True
    )

    # Check if path already exists
    if output_path.exists():
        if not allow_overwrite:
            raise ValidationError(
                f"Output path already exists: {output_path}. " "Use --force to overwrite."
            )

        # If it exists, verify type matches expectation
        if is_dir and not output_path.is_dir():
            raise ValidationError(f"Output path exists but is not a directory: {output_path}")
        elif not is_dir and output_path.is_dir():
            raise ValidationError(f"Output path exists but is a directory: {output_path}")

    return output_path


def sanitize_archive_member(member: tarfile.TarInfo, output_dir: Path) -> tarfile.TarInfo:
    """
    Sanitize a tar archive member to prevent path traversal attacks.

    Args:
        member: Tar member to sanitize
        output_dir: Output directory for extraction

    Returns:
        Sanitized tar member

    Raises:
        ValidationError: If member is malicious
    """
    # Get the member name
    member_name = member.name

    # Remove any leading slashes or drive letters
    member_name = member_name.lstrip("/\\")
    if len(member_name) > 1 and member_name[1] == ":":
        # Windows drive letter
        member_name = member_name[2:].lstrip("/\\")

    # Resolve the full path
    target_path = (output_dir / member_name).resolve()

    # Ensure the target path is within output_dir
    try:
        target_path.relative_to(output_dir.resolve())
    except ValueError:
        raise ValidationError(f"Archive member attempts path traversal: {member.name}") from None

    # Check for suspicious patterns
    if ".." in Path(member_name).parts:
        raise ValidationError(f"Archive member contains '..' component: {member.name}")

    # Check for absolute paths (should have been removed above, but double-check)
    if Path(member_name).is_absolute():
        raise ValidationError(f"Archive member has absolute path: {member.name}")

    # Update member name to sanitized version
    member.name = member_name

    return member


def check_archive_size(size: int, max_size: Optional[int] = None) -> None:
    """
    Check if archive size is within acceptable limits.

    Args:
        size: Size in bytes to check
        max_size: Maximum allowed size in bytes (None for no limit)

    Raises:
        ValidationError: If size exceeds maximum
    """
    if max_size is not None and size > max_size:
        # Convert to human-readable format
        def format_size(s: int) -> str:
            for unit in ["B", "KB", "MB", "GB", "TB"]:
                if s < 1024.0:
                    return f"{s:.2f} {unit}"
                s /= 1024.0
            return f"{s:.2f} PB"

        raise ValidationError(
            f"Archive size ({format_size(size)}) exceeds maximum "
            f"allowed size ({format_size(max_size)})"
        )


def validate_file_readable(path: Path) -> None:
    """
    Verify that a file is readable.

    Args:
        path: Path to check

    Raises:
        ValidationError: If file is not readable
    """
    if not os.access(path, os.R_OK):
        raise ValidationError(f"File is not readable: {path}")


def validate_directory_writable(path: Path) -> None:
    """
    Verify that a directory is writable.

    Args:
        path: Directory path to check

    Raises:
        ValidationError: If directory is not writable
    """
    if not os.access(path, os.W_OK):
        raise ValidationError(f"Directory is not writable: {path}")


def validate_input_paths(paths: List[Union[str, Path]]) -> List[Path]:
    """
    Validate a list of input paths for archiving.

    Args:
        paths: List of paths to validate

    Returns:
        List of validated Path objects

    Raises:
        ValidationError: If any path is invalid
    """
    if not paths:
        raise ValidationError("No input paths provided")

    validated = []
    for path in paths:
        validated_path = validate_path(
            path, must_exist=True, allow_symlinks=True  # Allow symlinks in input
        )

        # Check if readable
        try:
            validate_file_readable(validated_path)
        except ValidationError:
            # If it's a directory, check if it's traversable
            if validated_path.is_dir():
                if not os.access(validated_path, os.R_OK | os.X_OK):
                    raise ValidationError(f"Directory is not accessible: {validated_path}")
            else:
                raise

        validated.append(validated_path)

    return validated


def enforce_key_file_permissions(path: Path) -> None:
    """
    Set restrictive permissions on a key file.

    On Unix-like systems, sets permissions to 0600 (owner read/write only).
    On Windows, attempts to set appropriate ACLs.

    Args:
        path: Path to the key file
    """
    # Unix-like systems
    if hasattr(os, "chmod") and hasattr(stat, "S_IRUSR") and hasattr(stat, "S_IWUSR"):
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError as e:
            import warnings

            warnings.warn(f"Could not set restrictive permissions on key file: {e}", UserWarning)

    # Windows systems
    elif os.name == "nt":
        try:
            import subprocess

            # Use icacls to restrict access to current user only
            user = os.environ.get("USERNAME", os.environ.get("USER", ""))
            if user:
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                    check=False,
                    capture_output=True,
                )
        except Exception as e:
            import warnings

            warnings.warn(f"Could not set restrictive permissions on key file: {e}", UserWarning)
