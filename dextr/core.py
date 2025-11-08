"""
dextr/core.py

Core cryptographic engine for the dextr application.
This module contains all logic for key management, archiving, encryption, and decryption.
It is designed to be self-contained and raise exceptions on errors, without
performing any direct user I/O.

Security features:
- Path traversal protection
- Secure temporary file handling
- Key file permission enforcement
- Input validation
- Atomic file operations
"""

import getpass
import hashlib
import json
import os
import struct
import tarfile
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dextr.exceptions import (
    ArchivingError,
    DecryptionError,
    DextrError,
    EncryptionError,
    KeyManagementError,
    ValidationError,
)
from dextr.key_protection import (
    decrypt_key_with_password,
    encrypt_key_with_password,
    is_password_protected,
)
from dextr.logging_config import (
    get_logger,
    log_operation_complete,
    log_operation_error,
    log_operation_start,
    log_security_event,
)
from dextr.validation import (
    check_archive_size,
    enforce_key_file_permissions,
    sanitize_archive_member,
    validate_archive_file,
    validate_input_paths,
    validate_key_file,
    validate_output_path,
    validate_path,
)

# Get logger for this module
logger = get_logger(__name__)


# --- Constants ---
MAGIC_HEADER = b"DEXTR"
FORMAT_VERSION = 2  # Version 2 introduces archiving
KEY_ID_SIZE = 16
SALT_SIZE = 32
HEADER_FORMAT = f"<{len(MAGIC_HEADER)}sB{KEY_ID_SIZE}s{SALT_SIZE}s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

KEY_FILE_MAGIC = "DEXTR_KEY"
KEY_FILE_VERSION = 1
MASTER_KEY_SIZE = 64  # 512 bits

LAYER_KEY_SIZE = 32  # 256 bits
NUM_CRYPTO_LAYERS = 4
NONCE_SIZE = 12

HKDF_INFO_STRINGS = [
    b"dextr-layer-1-chacha20poly1305",
    b"dextr-layer-2-aes256gcm",
    b"dextr-layer-3-aes256gcm",
    b"dextr-layer-4-chacha20poly1305",
]


# --- Helper Functions ---
def _atomic_write(data: bytes, path: Path) -> None:
    """
    Atomically write data to a file.

    Writes to a temporary file and then atomically renames it.

    Args:
        data: Data to write
        path: Destination path

    Raises:
        IOError: If write fails
    """
    temp_fd = None
    temp_path = None

    try:
        # Create temporary file in same directory for atomic rename
        temp_fd, temp_path = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )

        # Write data
        with os.fdopen(temp_fd, "wb") as f:
            temp_fd = None  # fd now owned by file object
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        # Atomic rename
        os.replace(temp_path, path)
        temp_path = None

        logger.debug(f"Atomically wrote {len(data)} bytes to {path}")

    except Exception as e:
        # Clean up on error
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass

        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass

        raise IOError(f"Failed to write file: {e}") from e


def _create_secure_temp_file(suffix: str = "", dir: Optional[Path] = None) -> Tuple[int, Path]:
    """
    Create a secure temporary file.

    Args:
        suffix: Filename suffix
        dir: Directory for temp file (None for system default)

    Returns:
        Tuple of (file descriptor, path)
    """
    try:
        temp_fd, temp_path_str = tempfile.mkstemp(suffix=suffix, dir=dir)
        return temp_fd, Path(temp_path_str)
    except OSError as e:
        raise DextrError(f"Failed to create temporary file: {e}") from e


# --- Key Management ---
def generate_key_file(
    path: str,
    username: Optional[str] = None,
    enforce_permissions: bool = True,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a new encryption key file.

    Args:
        path: Path where key file will be created
        username: Username to record (detected if not provided)
        enforce_permissions: If True, set restrictive permissions on key file
        password: Optional password to encrypt the key file with

    Returns:
        Dictionary containing key metadata

    Raises:
        KeyManagementError: If key generation or file write fails
    """
    log_operation_start("generate_key_file", path=path)

    try:
        # Validate output path
        key_path = validate_output_path(path, allow_overwrite=False)

        # Get username
        if not username:
            try:
                username = getpass.getuser()
            except Exception:
                username = "unknown"
                logger.warning("Could not determine username")

        # Generate secure random key
        master_key = os.urandom(MASTER_KEY_SIZE)
        logger.debug(f"Generated {MASTER_KEY_SIZE}-byte master key")

        # Calculate key ID
        key_hash = hashlib.sha256(master_key).digest()
        key_id = key_hash[:KEY_ID_SIZE]

        # Create metadata
        metadata = {
            "magic": KEY_FILE_MAGIC,
            "version": KEY_FILE_VERSION,
            "created_by": username,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_id": key_id.hex(),
        }

        # Create key file data
        key_file_data = {"metadata": metadata, "master_key": master_key.hex()}

        # Optionally encrypt with password
        if password:
            logger.info("Encrypting key file with password")
            key_file_data = encrypt_key_with_password(key_file_data, password)

        # Write to file
        try:
            json_data = json.dumps(key_file_data, indent=2).encode("utf-8")
            _atomic_write(json_data, key_path)
        except IOError as e:
            raise KeyManagementError(f"Failed to write key file to {key_path}: {e}") from e

        # Set restrictive permissions
        if enforce_permissions:
            try:
                enforce_key_file_permissions(key_path)
                logger.info(f"Set restrictive permissions on {key_path}")
            except Exception as e:
                logger.warning(f"Could not set permissions: {e}")

        # Log security event
        log_security_event(
            "key_generated", {"path": str(key_path), "key_id": metadata["key_id"]}, level="INFO"
        )

        log_operation_complete("generate_key_file", path=str(key_path))
        return metadata

    except ValidationError as e:
        raise KeyManagementError(str(e)) from e
    except Exception as e:
        log_operation_error("generate_key_file", e, path=path)
        raise


def load_key_file(path: str, password: Optional[str] = None) -> Tuple[bytes, Dict[str, Any]]:
    """
    Load and validate an encryption key file.

    Args:
        path: Path to the key file
        password: Password for password-protected key files (None for unprotected)

    Returns:
        Tuple of (master_key bytes, metadata dictionary)

    Raises:
        KeyManagementError: If key file is invalid or cannot be read
    """
    log_operation_start("load_key_file", path=path)

    try:
        # Validate key file path
        key_path = validate_key_file(path)

        # Read file
        try:
            with open(key_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            raise KeyManagementError(f"Key file not found: {key_path}")
        except (json.JSONDecodeError, IOError) as e:
            raise KeyManagementError(f"Failed to read or parse key file: {e}") from e

        # Check if password-protected
        if is_password_protected(data):
            logger.info("Key file is password-protected")
            if not password:
                raise KeyManagementError(
                    "Key file is password-protected but no password provided. "
                    "Use --password or --password-file option."
                )
            # Decrypt with password
            data = decrypt_key_with_password(data, password)

        # Validate structure
        metadata = data.get("metadata", {})
        master_key_hex = data.get("master_key")

        if metadata.get("magic") != KEY_FILE_MAGIC:
            raise KeyManagementError("Invalid key file: incorrect magic number.")

        if not master_key_hex or not isinstance(master_key_hex, str):
            raise KeyManagementError("Invalid key file: master key is missing or malformed.")

        # Decode master key
        try:
            master_key = bytes.fromhex(master_key_hex)
        except ValueError as e:
            raise KeyManagementError(f"Invalid key file: master key is not valid hex. {e}") from e

        # Validate key size
        if len(master_key) != MASTER_KEY_SIZE:
            raise KeyManagementError(
                f"Invalid key file: master key must be {MASTER_KEY_SIZE} bytes long."
            )

        # Verify key ID matches
        expected_key_id = hashlib.sha256(master_key).digest()[:KEY_ID_SIZE].hex()
        if metadata.get("key_id") != expected_key_id:
            raise KeyManagementError("Key ID does not match master key. The file may be corrupt.")

        # Log security event
        log_security_event(
            "key_loaded", {"path": str(key_path), "key_id": metadata.get("key_id")}, level="INFO"
        )

        log_operation_complete("load_key_file", path=str(key_path))
        return master_key, metadata

    except ValidationError as e:
        raise KeyManagementError(str(e)) from e
    except Exception as e:
        log_operation_error("load_key_file", e, path=path)
        raise


# --- Core Cryptographic Logic ---
def _derive_layer_keys(master_key: bytes, salt: bytes) -> List[bytes]:
    """
    Derive encryption keys for all layers using HKDF.

    Args:
        master_key: Master encryption key
        salt: Random salt for key derivation

    Returns:
        List of derived keys
    """
    derived_keys = []
    for i in range(NUM_CRYPTO_LAYERS):
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=LAYER_KEY_SIZE, salt=salt, info=HKDF_INFO_STRINGS[i]
        )
        derived_keys.append(hkdf.derive(master_key))

    logger.debug(f"Derived {NUM_CRYPTO_LAYERS} layer keys")
    return derived_keys


def encrypt_paths(
    in_paths: List[str],
    out_path: str,
    master_key: bytes,
    max_size: Optional[int] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> None:
    """
    Archive and encrypt files/directories into a single encrypted archive.

    Args:
        in_paths: List of file/directory paths to encrypt
        out_path: Output path for encrypted archive (.dxe)
        master_key: Master encryption key (512 bits)
        max_size: Maximum archive size in bytes (None for no limit)
        progress_callback: Optional callback(stage, current, total) for progress

    Raises:
        ValidationError: If input validation fails
        ArchivingError: If archiving fails
        EncryptionError: If encryption fails
    """
    log_operation_start("encrypt_paths", num_paths=len(in_paths), output=out_path)

    temp_fd = None
    temp_path = None

    try:
        # Validate inputs
        validated_paths = validate_input_paths(in_paths)
        output_path = validate_archive_file(out_path, for_output=True)

        logger.info(f"Encrypting {len(validated_paths)} path(s) to {output_path}")

        # Stage 1: Create tar.xz archive
        if progress_callback:
            progress_callback("Creating archive", 0, 100)

        temp_fd, temp_path = _create_secure_temp_file(suffix=".tar.xz")

        try:
            with tarfile.open(fileobj=os.fdopen(temp_fd, "wb"), mode="w:xz") as tar:
                temp_fd = None  # fd now owned by tarfile

                for i, path in enumerate(validated_paths):
                    try:
                        arcname = os.path.basename(str(path))
                        tar.add(path, arcname=arcname)
                        logger.debug(f"Added to archive: {path} as {arcname}")

                        if progress_callback:
                            progress = int((i + 1) / len(validated_paths) * 30)
                            progress_callback("Creating archive", progress, 100)

                    except Exception as e:
                        raise ArchivingError(f"Failed to add '{path}' to archive: {e}") from e

        except tarfile.TarError as e:
            raise ArchivingError(f"Failed to create tar archive: {e}") from e

        # Read archive data
        with open(temp_path, "rb") as f:
            archive_data = f.read()

        archive_size = len(archive_data)
        logger.info(f"Created archive: {archive_size} bytes")

        # Check size limit
        if max_size is not None:
            check_archive_size(archive_size, max_size)

        # Stage 2: Compress with zlib
        if progress_callback:
            progress_callback("Compressing", 30, 100)

        compressed_data = zlib.compress(archive_data, level=9)
        logger.info(
            f"Compressed: {len(compressed_data)} bytes "
            f"({len(compressed_data)/archive_size*100:.1f}%)"
        )

        # Clear archive_data from memory
        del archive_data

        # Stage 3: Derive encryption keys
        if progress_callback:
            progress_callback("Deriving keys", 40, 100)

        salt = os.urandom(SALT_SIZE)
        layer_keys = _derive_layer_keys(master_key, salt)

        # Create cipher instances
        ciphers = [
            ChaCha20Poly1305(layer_keys[0]),
            AESGCM(layer_keys[1]),
            AESGCM(layer_keys[2]),
            ChaCha20Poly1305(layer_keys[3]),
        ]

        # Stage 4: Apply encryption layers
        data_to_encrypt = compressed_data
        del compressed_data  # Clear from memory

        try:
            for i, cipher in enumerate(ciphers):
                if progress_callback:
                    progress = 50 + int((i / len(ciphers)) * 40)
                    progress_callback(f"Encrypting layer {i+1}/{len(ciphers)}", progress, 100)

                nonce = os.urandom(NONCE_SIZE)
                data_to_encrypt = nonce + cipher.encrypt(nonce, data_to_encrypt, None)
                logger.debug(f"Applied encryption layer {i+1}")

        except Exception as e:
            raise EncryptionError(f"An error occurred during encryption layer: {e}") from e

        # Stage 5: Create final file with header
        if progress_callback:
            progress_callback("Writing output", 90, 100)

        key_id = hashlib.sha256(master_key).digest()[:KEY_ID_SIZE]
        header = struct.pack(HEADER_FORMAT, MAGIC_HEADER, FORMAT_VERSION, key_id, salt)
        final_data = header + data_to_encrypt

        # Write atomically
        try:
            _atomic_write(final_data, output_path)
        except IOError as e:
            raise EncryptionError(f"Failed to write output file: {e}") from e

        if progress_callback:
            progress_callback("Complete", 100, 100)

        logger.info(f"Encryption complete: {len(final_data)} bytes written")
        log_security_event(
            "archive_encrypted",
            {
                "output": str(output_path),
                "size": len(final_data),
                "num_inputs": len(validated_paths),
            },
            level="INFO",
        )

        log_operation_complete("encrypt_paths", output=str(output_path), size=len(final_data))

    except (ValidationError, ArchivingError, EncryptionError):
        raise
    except Exception as e:
        log_operation_error("encrypt_paths", e, output=out_path)
        raise EncryptionError(f"Unexpected error during encryption: {e}") from e

    finally:
        # Clean up temporary file
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass

        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logger.debug(f"Removed temporary file: {temp_path}")
            except OSError as e:
                logger.warning(f"Failed to remove temporary file: {e}")


def decrypt_archive(
    in_path: str,
    out_dir: str,
    master_key: bytes,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> None:
    """
    Decrypt and extract an encrypted archive.

    Args:
        in_path: Path to encrypted archive (.dxe)
        out_dir: Output directory for extracted files
        master_key: Master decryption key (512 bits)
        progress_callback: Optional callback(stage, current, total) for progress

    Raises:
        ValidationError: If input validation fails
        DecryptionError: If decryption or extraction fails
    """
    log_operation_start("decrypt_archive", input=in_path, output=out_dir)

    temp_fd = None
    temp_path = None

    try:
        # Validate inputs
        archive_path = validate_archive_file(in_path, for_output=False)
        output_dir = validate_path(out_dir, must_exist=False, parent_must_exist=False)

        # Create output directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Decrypting {archive_path} to {output_dir}")

        # Stage 1: Read encrypted file
        if progress_callback:
            progress_callback("Reading archive", 0, 100)

        try:
            with open(archive_path, "rb") as f:
                encrypted_data = f.read()
        except IOError as e:
            raise DecryptionError(f"Failed to read input file: {e}") from e

        total_size = len(encrypted_data)
        logger.info(f"Read encrypted archive: {total_size} bytes")

        # Stage 2: Parse header
        if progress_callback:
            progress_callback("Parsing header", 5, 100)

        if len(encrypted_data) < HEADER_SIZE:
            raise DecryptionError("Invalid file: content is smaller than the minimum header size.")

        header = encrypted_data[:HEADER_SIZE]
        ciphertext = encrypted_data[HEADER_SIZE:]
        magic, version, key_id, salt = struct.unpack(HEADER_FORMAT, header)

        # Validate header
        if magic != MAGIC_HEADER:
            raise DecryptionError("Invalid file: incorrect magic number.")

        if version > FORMAT_VERSION:
            raise DecryptionError(
                f"Unsupported file version: {version}. "
                f"This tool supports up to version {FORMAT_VERSION}."
            )

        # Verify key
        expected_key_id = hashlib.sha256(master_key).digest()[:KEY_ID_SIZE]
        if key_id != expected_key_id:
            raise DecryptionError("Key mismatch. This key file cannot decrypt this file.")

        logger.debug(f"Header validated: version={version}, key_id={key_id.hex()[:16]}...")

        # Stage 3: Derive keys
        if progress_callback:
            progress_callback("Deriving keys", 10, 100)

        layer_keys = _derive_layer_keys(master_key, salt)

        # Create cipher instances (in reverse order for decryption)
        ciphers = [
            ChaCha20Poly1305(layer_keys[0]),
            AESGCM(layer_keys[1]),
            AESGCM(layer_keys[2]),
            ChaCha20Poly1305(layer_keys[3]),
        ]

        # Stage 4: Decrypt layers
        data = ciphertext
        del ciphertext  # Clear from memory

        try:
            for i, cipher in enumerate(reversed(ciphers)):
                if progress_callback:
                    progress = 15 + int((i / len(ciphers)) * 40)
                    progress_callback(
                        f"Decrypting layer {len(ciphers)-i}/{len(ciphers)}", progress, 100
                    )

                nonce = data[:NONCE_SIZE]
                data = cipher.decrypt(nonce, data[NONCE_SIZE:], None)
                logger.debug(f"Decrypted layer {len(ciphers)-i}")

        except InvalidTag:
            raise DecryptionError(
                "Decryption failed: data integrity check failed. "
                "The file is corrupt or has been tampered with."
            )
        except Exception as e:
            raise DecryptionError(f"An error occurred during decryption layer: {e}") from e

        # Stage 5: Decompress
        if progress_callback:
            progress_callback("Decompressing", 60, 100)

        try:
            archive_data = zlib.decompress(data)
            logger.info(f"Decompressed: {len(archive_data)} bytes")
        except zlib.error as e:
            raise DecryptionError(f"Failed to decompress payload: {e}") from e

        del data  # Clear from memory

        # Stage 6: Extract archive
        if progress_callback:
            progress_callback("Extracting files", 70, 100)

        temp_fd, temp_path = _create_secure_temp_file(suffix=".tar.xz")

        try:
            # Write decompressed data to temp file
            with os.fdopen(temp_fd, "wb") as f:
                temp_fd = None  # fd now owned by file object
                f.write(archive_data)
                f.flush()

            # Extract with path validation
            with tarfile.open(temp_path, mode="r:xz") as tar:
                # Validate and sanitize each member before extraction
                members_to_extract = []
                for member in tar.getmembers():
                    try:
                        sanitized_member = sanitize_archive_member(member, output_dir)
                        members_to_extract.append(sanitized_member)
                    except ValidationError as e:
                        logger.warning(f"Skipping malicious archive member: {e}")
                        continue

                # Extract all validated members
                for member in members_to_extract:
                    tar.extract(member, path=output_dir)

                logger.info(f"Extracted {len(members_to_extract)} items to {output_dir}")

        except tarfile.TarError as e:
            raise DecryptionError(f"Failed to extract archive: {e}") from e

        if progress_callback:
            progress_callback("Complete", 100, 100)

        log_security_event(
            "archive_decrypted",
            {
                "input": str(archive_path),
                "output": str(output_dir),
                "num_extracted": len(members_to_extract),
            },
            level="INFO",
        )

        log_operation_complete("decrypt_archive", input=str(archive_path), output=str(output_dir))

    except (ValidationError, DecryptionError):
        raise
    except Exception as e:
        log_operation_error("decrypt_archive", e, input=in_path)
        raise DecryptionError(f"Unexpected error during decryption: {e}") from e

    finally:
        # Clean up temporary file
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass

        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logger.debug(f"Removed temporary file: {temp_path}")
            except OSError as e:
                logger.warning(f"Failed to remove temporary file: {e}")


def get_archive_info(path: str) -> Dict[str, Any]:
    """
    Get metadata from an encrypted archive without decrypting.

    Args:
        path: Path to encrypted archive

    Returns:
        Dictionary with archive information

    Raises:
        DecryptionError: If archive is invalid
    """
    try:
        archive_path = validate_archive_file(path, for_output=False)

        with open(archive_path, "rb") as f:
            header_data = f.read(HEADER_SIZE)

        if len(header_data) < HEADER_SIZE:
            raise DecryptionError("Invalid archive: header too small")

        magic, version, key_id, salt = struct.unpack(HEADER_FORMAT, header_data)

        if magic != MAGIC_HEADER:
            raise DecryptionError("Invalid archive: incorrect magic number")

        file_size = archive_path.stat().st_size

        return {
            "format_version": version,
            "key_id": key_id.hex(),
            "salt": salt.hex(),
            "file_size": file_size,
            "encrypted_size": file_size - HEADER_SIZE,
        }

    except Exception as e:
        raise DecryptionError(f"Failed to read archive info: {e}") from e


def check_archive_integrity(in_path: str, master_key: bytes, quick: bool = False) -> Dict[str, Any]:
    """
    Check the integrity of an encrypted archive.

    Performs a partial decryption to verify the archive can be decrypted
    with the provided key. Can perform either a quick check (header + first layer)
    or a full check (complete decryption without extraction).

    Args:
        in_path: Path to encrypted archive (.dxe)
        master_key: Master decryption key (512 bits)
        quick: If True, only check first decryption layer (faster)

    Returns:
        Dictionary with integrity check results:
        - valid: Boolean indicating if archive passed checks
        - header_valid: Header structure valid
        - key_match: Key ID matches provided key
        - decrypt_success: Decryption succeeded (at least first layer)
        - full_decrypt_success: All layers decrypted (if quick=False)
        - error: Error message if validation failed

    Raises:
        ValidationError: If input validation fails
        DecryptionError: If integrity check cannot be performed
    """
    log_operation_start("check_archive_integrity", input=in_path, quick=quick)

    result = {
        "valid": False,
        "header_valid": False,
        "key_match": False,
        "decrypt_success": False,
        "full_decrypt_success": False,
        "error": None,
    }

    try:
        # Validate input
        archive_path = validate_archive_file(in_path, for_output=False)

        logger.info(f"Checking integrity of {archive_path}")

        # Read encrypted file
        try:
            with open(archive_path, "rb") as f:
                encrypted_data = f.read()
        except IOError as e:
            result["error"] = f"Failed to read archive: {e}"
            return result

        total_size = len(encrypted_data)
        logger.debug(f"Archive size: {total_size} bytes")

        # Check header
        if len(encrypted_data) < HEADER_SIZE:
            result["error"] = "Archive too small (header incomplete)"
            return result

        header = encrypted_data[:HEADER_SIZE]
        ciphertext = encrypted_data[HEADER_SIZE:]
        magic, version, key_id, salt = struct.unpack(HEADER_FORMAT, header)

        # Validate header
        if magic != MAGIC_HEADER:
            result["error"] = "Invalid magic number in header"
            return result

        result["header_valid"] = True

        if version > FORMAT_VERSION:
            result["error"] = f"Unsupported format version: {version}"
            return result

        # Verify key matches
        expected_key_id = hashlib.sha256(master_key).digest()[:KEY_ID_SIZE]
        if key_id != expected_key_id:
            result["error"] = "Key ID mismatch - wrong key provided"
            return result

        result["key_match"] = True

        # Derive keys
        layer_keys = _derive_layer_keys(master_key, salt)

        # Create cipher instances (in reverse order for decryption)
        ciphers = [
            ChaCha20Poly1305(layer_keys[0]),
            AESGCM(layer_keys[1]),
            AESGCM(layer_keys[2]),
            ChaCha20Poly1305(layer_keys[3]),
        ]

        # Decrypt layers
        data = ciphertext

        if quick:
            # Quick check: only decrypt first layer
            try:
                cipher = ciphers[3]  # Last cipher for first layer
                nonce = data[:NONCE_SIZE]
                data = cipher.decrypt(nonce, data[NONCE_SIZE:], None)
                result["decrypt_success"] = True
                result["valid"] = True
                logger.info("Quick integrity check passed")
            except InvalidTag:
                result["error"] = "First decryption layer failed - data corrupted or wrong key"
                return result
            except Exception as e:
                result["error"] = f"Decryption error: {e}"
                return result

        else:
            # Full check: decrypt all layers
            try:
                for i, cipher in enumerate(reversed(ciphers)):
                    nonce = data[:NONCE_SIZE]
                    data = cipher.decrypt(nonce, data[NONCE_SIZE:], None)
                    logger.debug(f"Decrypted layer {len(ciphers)-i}")

                result["decrypt_success"] = True

                # Try to decompress
                try:
                    decompressed = zlib.decompress(data)
                    logger.debug(f"Decompressed: {len(decompressed)} bytes")
                    result["full_decrypt_success"] = True
                    result["valid"] = True
                    logger.info("Full integrity check passed")
                except zlib.error as e:
                    result["error"] = f"Decompression failed: {e}"
                    return result

            except InvalidTag:
                result["error"] = "Decryption failed - data corrupted or tampered"
                return result
            except Exception as e:
                result["error"] = f"Decryption error: {e}"
                return result

        log_operation_complete("check_archive_integrity", valid=result["valid"])
        return result

    except ValidationError as e:
        result["error"] = str(e)
        raise
    except Exception as e:
        result["error"] = str(e)
        log_operation_error("check_archive_integrity", e, input=in_path)
        raise DecryptionError(f"Integrity check failed: {e}") from e
