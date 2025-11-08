"""
dextr/key_protection.py

Password-based encryption for key files.
Provides optional password protection for .dxk key files using PBKDF2 key derivation
and AES-256-GCM encryption.

This module allows users to encrypt their master key files with a password for
additional security when storing keys.
"""

import os
import json
import getpass
import hashlib
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
except ImportError:
    raise ImportError(
        "The 'cryptography' library is not installed. "
        "Please install it with: pip install cryptography"
    )

from dextr.exceptions import KeyManagementError


# Constants
PASSWORD_PROTECTED_MAGIC = 'DEXTR_KEY_PROTECTED'
PASSWORD_SALT_SIZE = 32  # 256 bits
PASSWORD_NONCE_SIZE = 12  # 96 bits for AES-GCM
PASSWORD_ITERATIONS = 600000  # OWASP recommendation for 2024
PASSWORD_KEY_SIZE = 32  # 256 bits


def _derive_password_key(password: str, salt: bytes, iterations: int = PASSWORD_ITERATIONS) -> bytes:
    """
    Derive an encryption key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: User password
        salt: Random salt for key derivation
        iterations: Number of PBKDF2 iterations

    Returns:
        Derived encryption key (32 bytes)
    """
    password_bytes = password.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PASSWORD_KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )

    return kdf.derive(password_bytes)


def encrypt_key_with_password(
    key_data: Dict[str, Any],
    password: str,
    iterations: int = PASSWORD_ITERATIONS
) -> Dict[str, Any]:
    """
    Encrypt a key file's data with a password.

    The key file JSON is encrypted using AES-256-GCM with a key derived
    from the password using PBKDF2-HMAC-SHA256.

    Args:
        key_data: Dictionary containing key file data (metadata and master_key)
        password: Password to encrypt the key with
        iterations: Number of PBKDF2 iterations (default: 600000)

    Returns:
        Dictionary with encrypted key data

    Raises:
        KeyManagementError: If encryption fails
    """
    try:
        # Generate random salt and nonce
        salt = os.urandom(PASSWORD_SALT_SIZE)
        nonce = os.urandom(PASSWORD_NONCE_SIZE)

        # Derive encryption key from password
        encryption_key = _derive_password_key(password, salt, iterations)

        # Serialize the key data to JSON
        json_data = json.dumps(key_data).encode('utf-8')

        # Encrypt with AES-GCM
        cipher = AESGCM(encryption_key)
        ciphertext = cipher.encrypt(nonce, json_data, None)

        # Create protected key structure
        protected_data = {
            'magic': PASSWORD_PROTECTED_MAGIC,
            'version': 1,
            'iterations': iterations,
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex()
        }

        return protected_data

    except Exception as e:
        raise KeyManagementError(
            f"Failed to encrypt key with password: {e}"
        ) from e


def decrypt_key_with_password(
    protected_data: Dict[str, Any],
    password: str
) -> Dict[str, Any]:
    """
    Decrypt a password-protected key file.

    Args:
        protected_data: Dictionary containing encrypted key data
        password: Password to decrypt the key with

    Returns:
        Decrypted key file data (metadata and master_key)

    Raises:
        KeyManagementError: If decryption fails or password is incorrect
    """
    try:
        # Validate structure
        if protected_data.get('magic') != PASSWORD_PROTECTED_MAGIC:
            raise KeyManagementError(
                "Invalid protected key file: incorrect magic number"
            )

        version = protected_data.get('version', 1)
        if version != 1:
            raise KeyManagementError(
                f"Unsupported protected key version: {version}"
            )

        # Extract encrypted components
        iterations = protected_data.get('iterations', PASSWORD_ITERATIONS)
        salt = bytes.fromhex(protected_data['salt'])
        nonce = bytes.fromhex(protected_data['nonce'])
        ciphertext = bytes.fromhex(protected_data['ciphertext'])

        # Derive decryption key from password
        decryption_key = _derive_password_key(password, salt, iterations)

        # Decrypt with AES-GCM
        cipher = AESGCM(decryption_key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise KeyManagementError(
                "Incorrect password or corrupted key file"
            )

        # Parse decrypted JSON
        key_data = json.loads(plaintext.decode('utf-8'))

        return key_data

    except KeyManagementError:
        raise
    except Exception as e:
        raise KeyManagementError(
            f"Failed to decrypt key with password: {e}"
        ) from e


def is_password_protected(key_file_data: Dict[str, Any]) -> bool:
    """
    Check if a key file is password-protected.

    Args:
        key_file_data: Dictionary loaded from key file

    Returns:
        True if key file is password-protected, False otherwise
    """
    return key_file_data.get('magic') == PASSWORD_PROTECTED_MAGIC


def prompt_password(
    prompt_text: str = "Enter password: ",
    confirm: bool = False
) -> str:
    """
    Prompt user for a password securely.

    Uses getpass for secure password input (doesn't echo to terminal).

    Args:
        prompt_text: Text to display when prompting
        confirm: If True, ask for password twice and verify they match

    Returns:
        Password string

    Raises:
        KeyManagementError: If passwords don't match (when confirm=True)
    """
    try:
        password = getpass.getpass(prompt_text)

        if confirm:
            password2 = getpass.getpass("Confirm password: ")
            if password != password2:
                raise KeyManagementError("Passwords do not match")

        if not password:
            raise KeyManagementError("Password cannot be empty")

        return password

    except (KeyboardInterrupt, EOFError):
        raise KeyManagementError("Password input cancelled")
    except Exception as e:
        raise KeyManagementError(f"Failed to read password: {e}") from e


def read_password_from_file(file_path: str) -> str:
    """
    Read password from a file.

    Useful for automation and scripting. The password should be the only
    content in the file (trailing newline is stripped).

    Args:
        file_path: Path to file containing password

    Returns:
        Password string

    Raises:
        KeyManagementError: If file cannot be read
    """
    try:
        password_path = Path(file_path)

        if not password_path.exists():
            raise KeyManagementError(f"Password file not found: {file_path}")

        if not password_path.is_file():
            raise KeyManagementError(f"Password path is not a file: {file_path}")

        with open(password_path, 'r', encoding='utf-8') as f:
            password = f.read().strip()

        if not password:
            raise KeyManagementError("Password file is empty")

        return password

    except KeyManagementError:
        raise
    except Exception as e:
        raise KeyManagementError(
            f"Failed to read password from file: {e}"
        ) from e


def get_password_strength(password: str) -> Dict[str, Any]:
    """
    Evaluate password strength.

    Provides basic password strength assessment for user feedback.

    Args:
        password: Password to evaluate

    Returns:
        Dictionary with strength information:
        - strength: "weak", "medium", "strong"
        - length: Password length
        - has_upper: Has uppercase letters
        - has_lower: Has lowercase letters
        - has_digits: Has digits
        - has_special: Has special characters
        - score: Numeric score (0-100)
    """
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    # Calculate score
    score = 0

    # Length scoring
    if length >= 8:
        score += 20
    if length >= 12:
        score += 20
    if length >= 16:
        score += 10

    # Complexity scoring
    if has_upper:
        score += 15
    if has_lower:
        score += 15
    if has_digits:
        score += 10
    if has_special:
        score += 10

    # Determine strength category
    if score < 40:
        strength = "weak"
    elif score < 70:
        strength = "medium"
    else:
        strength = "strong"

    return {
        'strength': strength,
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digits': has_digits,
        'has_special': has_special,
        'score': score
    }


def generate_password_hint(password: str, max_hint_length: int = 50) -> str:
    """
    Generate a password hint based on password characteristics.

    Args:
        password: Password to generate hint for
        max_hint_length: Maximum length of hint text

    Returns:
        Password hint string
    """
    strength_info = get_password_strength(password)

    hints = []

    if strength_info['length'] < 12:
        hints.append("consider using at least 12 characters")

    if not strength_info['has_upper']:
        hints.append("add uppercase letters")

    if not strength_info['has_lower']:
        hints.append("add lowercase letters")

    if not strength_info['has_digits']:
        hints.append("add numbers")

    if not strength_info['has_special']:
        hints.append("add special characters")

    if not hints:
        return "Password strength: strong"

    hint = "Password strength: " + strength_info['strength'] + " - " + ", ".join(hints)

    if len(hint) > max_hint_length:
        hint = hint[:max_hint_length-3] + "..."

    return hint
