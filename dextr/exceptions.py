"""
dextr/exceptions.py

Exception hierarchy for the dextr application.
All custom exceptions are defined here to avoid circular imports.
"""


class DextrError(Exception):
    """
    Base exception for all dextr-related errors.

    All custom exceptions in the dextr package inherit from this base class,
    allowing users to catch all dextr-specific errors with a single except clause.
    """
    pass


class KeyManagementError(DextrError):
    """
    Errors related to key file operations.

    Raised when:
    - Key file generation fails
    - Key file cannot be read or parsed
    - Key file has invalid format or content
    - Key file permissions cannot be set
    """
    pass


class ArchivingError(DextrError):
    """
    Errors related to file archiving operations.

    Raised when:
    - Creating tar.xz archive fails
    - Adding files to archive fails
    - Archive format is invalid
    - Temporary archive operations fail
    """
    pass


class EncryptionError(DextrError):
    """
    Errors occurring during the encryption process.

    Raised when:
    - Encryption layer application fails
    - Key derivation fails
    - Output file cannot be written
    - Compression fails
    """
    pass


class DecryptionError(DextrError):
    """
    Errors occurring during the decryption process.

    Raised when:
    - Wrong decryption key is used
    - Archive is corrupted or tampered with
    - Decryption layer fails
    - Decompression fails
    - Archive extraction fails
    - Archive format version is unsupported
    """
    pass


class ValidationError(DextrError):
    """
    Errors related to input validation.

    Raised when:
    - Invalid file paths are provided
    - Path traversal attempts are detected
    - File permissions are insufficient
    - Archive size exceeds limits
    - Malicious archive members are detected
    """
    pass


# For backward compatibility and convenience, export all exceptions
__all__ = [
    'DextrError',
    'KeyManagementError',
    'ArchivingError',
    'EncryptionError',
    'DecryptionError',
    'ValidationError',
]
