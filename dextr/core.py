"""
dextr/core.py

Core cryptographic engine for the dextr application.
This module contains all logic for key management, archiving, encryption, and decryption.
It is designed to be self-contained and raise exceptions on errors, without
performing any direct user I/O.
"""

import os
import json
import zlib
import struct
import getpass
import hashlib
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
except ImportError:
    raise ImportError("The 'cryptography' library is not installed. Please install it with: pip install cryptography")

# --- Constants ---
MAGIC_HEADER = b'DEXTR'
FORMAT_VERSION = 2  # Version 2 introduces archiving
KEY_ID_SIZE = 16
SALT_SIZE = 32
HEADER_FORMAT = f'<{len(MAGIC_HEADER)}sB{KEY_ID_SIZE}s{SALT_SIZE}s'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

KEY_FILE_MAGIC = 'DEXTR_KEY'
KEY_FILE_VERSION = 1
MASTER_KEY_SIZE = 64  # 512 bits

LAYER_KEY_SIZE = 32  # 256 bits
NUM_CRYPTO_LAYERS = 4
NONCE_SIZE = 12

HKDF_INFO_STRINGS = [
    b'dextr-layer-1-chacha20poly1305',
    b'dextr-layer-2-aes256gcm',
    b'dextr-layer-3-aes256gcm',
    b'dextr-layer-4-chacha20poly1305',
]

# --- Custom Exceptions ---
class DextrError(Exception):
    """Base exception for all dextr-related errors."""
    pass

class KeyManagementError(DextrError):
    """Errors related to key file operations."""
    pass

class ArchivingError(DextrError):
    """Errors related to file archiving."""
    pass

class EncryptionError(DextrError):
    """Errors occurring during the encryption process."""
    pass

class DecryptionError(DextrError):
    """Errors occurring during the decryption process."""
    pass

# --- Key Management ---
def generate_key_file(path: str, username: str = None) -> Dict[str, Any]:
    if not username:
        try:
            username = getpass.getuser()
        except Exception:
            username = "unknown"

    master_key = os.urandom(MASTER_KEY_SIZE)
    key_hash = hashlib.sha256(master_key).digest()
    key_id = key_hash[:KEY_ID_SIZE]

    metadata = {
        "magic": KEY_FILE_MAGIC,
        "version": KEY_FILE_VERSION,
        "created_by": username,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "key_id": key_id.hex(),
    }
    key_file_data = {"metadata": metadata, "master_key": master_key.hex()}

    try:
        with open(path, 'w') as f:
            json.dump(key_file_data, f, indent=2)
    except IOError as e:
        raise KeyManagementError(f"Failed to write key file to {path}: {e}") from e
    return metadata

def load_key_file(path: str) -> Tuple[bytes, Dict[str, Any]]:
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        raise KeyManagementError(f"Key file not found: {path}")
    except (json.JSONDecodeError, IOError) as e:
        raise KeyManagementError(f"Failed to read or parse key file: {e}") from e

    metadata = data.get("metadata", {})
    master_key_hex = data.get("master_key")

    if metadata.get("magic") != KEY_FILE_MAGIC:
        raise KeyManagementError("Invalid key file: incorrect magic number.")
    if not master_key_hex or not isinstance(master_key_hex, str):
        raise KeyManagementError("Invalid key file: master key is missing or malformed.")

    try:
        master_key = bytes.fromhex(master_key_hex)
    except ValueError as e:
        raise KeyManagementError(f"Invalid key file: master key is not valid hex. {e}") from e

    if len(master_key) != MASTER_KEY_SIZE:
        raise KeyManagementError(f"Invalid key file: master key must be {MASTER_KEY_SIZE} bytes long.")

    expected_key_id = hashlib.sha256(master_key).digest()[:KEY_ID_SIZE].hex()
    if metadata.get("key_id") != expected_key_id:
        raise KeyManagementError("Key ID does not match master key. The file may be corrupt.")

    return master_key, metadata

# --- Core Logic ---
def _derive_layer_keys(master_key: bytes, salt: bytes) -> list:
    derived_keys = []
    for i in range(NUM_CRYPTO_LAYERS):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=LAYER_KEY_SIZE, salt=salt, info=HKDF_INFO_STRINGS[i])
        derived_keys.append(hkdf.derive(master_key))
    return derived_keys

def encrypt_paths(in_paths: List[str], out_path: str, master_key: bytes) -> None:
    temp_fd, temp_path = -1, None
    try:
        temp_fd, temp_path = tempfile.mkstemp(suffix=".tar.xz")
        with tarfile.open(fileobj=os.fdopen(temp_fd, 'wb'), mode='w:xz') as tar:
            for path in in_paths:
                try:
                    tar.add(path, arcname=os.path.basename(path))
                except Exception as e:
                    raise ArchivingError(f"Failed to add '{path}' to archive: {e}") from e
        
        with open(temp_path, 'rb') as f:
            archive_data = f.read()

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        elif temp_fd != -1:
            os.close(temp_fd)

    # Layer 1: Compression (zlib on top of LZMA archive)
    compressed_data = zlib.compress(archive_data, level=9)

    salt = os.urandom(SALT_SIZE)
    layer_keys = _derive_layer_keys(master_key, salt)
    ciphers = [ChaCha20Poly1305(layer_keys[0]), AESGCM(layer_keys[1]), AESGCM(layer_keys[2]), ChaCha20Poly1305(layer_keys[3])]

    data_to_encrypt = compressed_data
    try:
        for cipher in ciphers:
            nonce = os.urandom(NONCE_SIZE)
            data_to_encrypt = nonce + cipher.encrypt(nonce, data_to_encrypt, None)
    except Exception as e:
        raise EncryptionError(f"An error occurred during an encryption layer: {e}") from e

    key_id = hashlib.sha256(master_key).digest()[:KEY_ID_SIZE]
    header = struct.pack(HEADER_FORMAT, MAGIC_HEADER, FORMAT_VERSION, key_id, salt)
    final_data = header + data_to_encrypt

    try:
        with open(out_path, 'wb') as f:
            f.write(final_data)
    except IOError as e:
        raise EncryptionError(f"Failed to write output file: {e}") from e

def decrypt_archive(in_path: str, out_dir: str, master_key: bytes) -> None:
    try:
        with open(in_path, 'rb') as f:
            encrypted_data = f.read()
    except IOError as e:
        raise DecryptionError(f"Failed to read input file: {e}") from e

    if len(encrypted_data) < HEADER_SIZE:
        raise DecryptionError("Invalid file: content is smaller than the minimum header size.")

    header = encrypted_data[:HEADER_SIZE]
    ciphertext = encrypted_data[HEADER_SIZE:]
    magic, version, key_id, salt = struct.unpack(HEADER_FORMAT, header)

    if magic != MAGIC_HEADER:
        raise DecryptionError("Invalid file: incorrect magic number.")
    if version > FORMAT_VERSION:
        raise DecryptionError(f"Unsupported file version: {version}. This tool supports up to version {FORMAT_VERSION}.")

    expected_key_id = hashlib.sha256(master_key).digest()[:KEY_ID_SIZE]
    if key_id != expected_key_id:
        raise DecryptionError("Key mismatch. This key file cannot decrypt this file.")

    layer_keys = _derive_layer_keys(master_key, salt)
    ciphers = [ChaCha20Poly1305(layer_keys[0]), AESGCM(layer_keys[1]), AESGCM(layer_keys[2]), ChaCha20Poly1305(layer_keys[3])]

    data = ciphertext
    try:
        for cipher in reversed(ciphers):
            nonce = data[:NONCE_SIZE]
            data = cipher.decrypt(nonce, data[NONCE_SIZE:], None)
    except InvalidTag:
        raise DecryptionError("Decryption failed: data integrity check failed. The file is corrupt or has been tampered with.")
    except Exception as e:
        raise DecryptionError(f"An error occurred during a decryption layer: {e}") from e

    try:
        archive_data = zlib.decompress(data)
    except zlib.error as e:
        raise DecryptionError(f"Failed to decompress payload: {e}") from e

    temp_fd, temp_path = -1, None
    try:
        temp_fd, temp_path = tempfile.mkstemp(suffix=".tar.xz")
        with os.fdopen(temp_fd, 'wb') as f:
            f.write(archive_data)
        
        with tarfile.open(temp_path, mode='r:xz') as tar:
            tar.extractall(path=out_dir)

    except tarfile.TarError as e:
        raise DecryptionError(f"Failed to extract archive: {e}") from e
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        elif temp_fd != -1:
            os.close(temp_fd)