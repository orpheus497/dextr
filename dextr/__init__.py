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

__version__ = '1.1.0'
__author__ = 'orpheus497'
__license__ = 'MIT'

# Import core functionality
from dextr.core import (
    # Key management functions
    generate_key_file,
    load_key_file,

    # Encryption/decryption functions
    encrypt_paths,
    decrypt_archive,

    # Exceptions
    DextrError,
    KeyManagementError,
    ArchivingError,
    EncryptionError,
    DecryptionError,

    # Constants (useful for advanced users)
    MAGIC_HEADER,
    FORMAT_VERSION,
    KEY_FILE_MAGIC,
    KEY_FILE_VERSION,
    MASTER_KEY_SIZE,
)

# Define public API
__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__license__',

    # Functions
    'generate_key_file',
    'load_key_file',
    'encrypt_paths',
    'decrypt_archive',

    # Exceptions
    'DextrError',
    'KeyManagementError',
    'ArchivingError',
    'EncryptionError',
    'DecryptionError',

    # Constants
    'MAGIC_HEADER',
    'FORMAT_VERSION',
    'KEY_FILE_MAGIC',
    'KEY_FILE_VERSION',
    'MASTER_KEY_SIZE',
]
