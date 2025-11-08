"""
dextr - Secure Archiving & Encryption System

A command-line tool for multi-layer authenticated encryption of files and directories.

Original Concept by orpheus497

This package provides:
- Secure key generation and management
- Multi-layer AEAD encryption (ChaCha20-Poly1305 and AES-256-GCM)
- HKDF-SHA256 key derivation
- tar.xz archiving with zlib compression
- Cross-platform support (Linux, macOS, Windows, Termux)

Example usage:
    >>> from dextr import generate_key_file, encrypt_paths, decrypt_archive, load_key_file
    >>>
    >>> # Generate a key file
    >>> metadata = generate_key_file('mykey.dxk')
    >>>
    >>> # Load the key
    >>> master_key, metadata = load_key_file('mykey.dxk')
    >>>
    >>> # Encrypt files
    >>> encrypt_paths(['file1.txt', 'folder/'], 'backup.dxe', master_key)
    >>>
    >>> # Decrypt archive
    >>> decrypt_archive('backup.dxe', 'restored/', master_key)
"""

# Import version from single source of truth
from dextr.version import __version__, __version_info__

__author__ = "orpheus497"
__license__ = "MIT"

# Import exceptions
from dextr.exceptions import (
    DextrError,
    KeyManagementError,
    ArchivingError,
    EncryptionError,
    DecryptionError,
    ValidationError,
)

# Import core functionality
from dextr.core import (
    # Key management functions
    generate_key_file,
    load_key_file,
    # Encryption/decryption functions
    encrypt_paths,
    decrypt_archive,
    get_archive_info,
    check_archive_integrity,
    # Constants (useful for advanced users)
    MAGIC_HEADER,
    FORMAT_VERSION,
    KEY_FILE_MAGIC,
    KEY_FILE_VERSION,
    MASTER_KEY_SIZE,
)

# Import password protection utilities
from dextr.key_protection import (
    encrypt_key_with_password,
    decrypt_key_with_password,
    is_password_protected,
    prompt_password,
    read_password_from_file,
    get_password_strength,
)

# Define public API
__all__ = [
    # Version info
    "__version__",
    "__version_info__",
    "__author__",
    "__license__",
    # Functions
    "generate_key_file",
    "load_key_file",
    "encrypt_paths",
    "decrypt_archive",
    "get_archive_info",
    "check_archive_integrity",
    # Password protection
    "encrypt_key_with_password",
    "decrypt_key_with_password",
    "is_password_protected",
    "prompt_password",
    "read_password_from_file",
    "get_password_strength",
    # Exceptions
    "DextrError",
    "KeyManagementError",
    "ArchivingError",
    "EncryptionError",
    "DecryptionError",
    "ValidationError",
    # Constants
    "MAGIC_HEADER",
    "FORMAT_VERSION",
    "KEY_FILE_MAGIC",
    "KEY_FILE_VERSION",
    "MASTER_KEY_SIZE",
]
