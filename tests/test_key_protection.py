"""
tests/test_key_protection.py

Tests for password-based key file protection.
Tests password encryption, decryption, strength evaluation, and error handling.
"""

import pytest
from pathlib import Path

from dextr import (
    generate_key_file,
    load_key_file,
    encrypt_paths,
    decrypt_archive,
)
from dextr.key_protection import (
    encrypt_key_with_password,
    decrypt_key_with_password,
    is_password_protected,
    read_password_from_file,
    get_password_strength,
)
from dextr.exceptions import KeyManagementError


class TestPasswordProtection:
    """Test password-based key file encryption."""

    def test_generate_password_protected_key(self, temp_dir):
        """Test generating a password-protected key file."""
        key_path = temp_dir / "protected.dxk"
        password = "MySecurePassword123!"

        metadata = generate_key_file(str(key_path), password=password)

        assert key_path.exists()
        assert metadata['key_id'] is not None

    def test_load_password_protected_key(self, password_protected_key):
        """Test loading a password-protected key file."""
        key_path, password, master_key, metadata = password_protected_key

        # Should load successfully with correct password
        loaded_key, loaded_metadata = load_key_file(key_path, password=password)

        assert loaded_key == master_key
        assert loaded_metadata['key_id'] == metadata['key_id']

    def test_load_without_password_fails(self, password_protected_key):
        """Test loading password-protected key without password fails."""
        key_path, password, master_key, metadata = password_protected_key

        with pytest.raises(KeyManagementError, match="password"):
            load_key_file(key_path)

    def test_load_with_wrong_password_fails(self, password_protected_key):
        """Test loading with wrong password fails."""
        key_path, correct_password, master_key, metadata = password_protected_key

        with pytest.raises(KeyManagementError, match="password|Incorrect"):
            load_key_file(key_path, password="WrongPassword!")

    def test_password_roundtrip(self, temp_dir):
        """Test that password encryption/decryption preserves key data."""
        # Generate regular key
        regular_key_path = temp_dir / "regular.dxk"
        metadata1 = generate_key_file(str(regular_key_path))
        master_key1, _ = load_key_file(str(regular_key_path))

        # Generate password-protected key
        protected_key_path = temp_dir / "protected.dxk"
        password = "TestPassword123!"
        metadata2 = generate_key_file(str(protected_key_path), password=password)
        master_key2, _ = load_key_file(str(protected_key_path), password=password)

        # Both should have 512-bit keys
        assert len(master_key1) == 64
        assert len(master_key2) == 64

        # Keys should be different (randomly generated)
        assert master_key1 != master_key2

    def test_is_password_protected_detection(self, temp_dir):
        """Test detection of password-protected key files."""
        # Create regular key
        regular_key_path = temp_dir / "regular.dxk"
        generate_key_file(str(regular_key_path))

        # Create protected key
        protected_key_path = temp_dir / "protected.dxk"
        password = "TestPass123!"
        generate_key_file(str(protected_key_path), password=password)

        # Load and check
        import json
        with open(regular_key_path, 'r') as f:
            regular_data = json.load(f)
        with open(protected_key_path, 'r') as f:
            protected_data = json.load(f)

        assert not is_password_protected(regular_data)
        assert is_password_protected(protected_data)


class TestPasswordFileReading:
    """Test reading passwords from files."""

    def test_read_password_from_file(self, temp_dir):
        """Test reading password from a file."""
        password_file = temp_dir / "password.txt"
        password = "MyPassword123!"
        password_file.write_text(password)

        loaded_password = read_password_from_file(str(password_file))

        assert loaded_password == password

    def test_read_password_strips_newline(self, temp_dir):
        """Test that password file reading strips trailing newline."""
        password_file = temp_dir / "password.txt"
        password = "MyPassword123!"
        password_file.write_text(password + "\n")

        loaded_password = read_password_from_file(str(password_file))

        assert loaded_password == password
        assert '\n' not in loaded_password

    def test_read_password_from_nonexistent_file(self, temp_dir):
        """Test reading from nonexistent file fails."""
        with pytest.raises(KeyManagementError):
            read_password_from_file(str(temp_dir / "doesnotexist.txt"))

    def test_read_empty_password_file(self, temp_dir):
        """Test reading from empty file fails."""
        password_file = temp_dir / "empty.txt"
        password_file.write_text("")

        with pytest.raises(KeyManagementError, match="empty"):
            read_password_from_file(str(password_file))


class TestPasswordStrength:
    """Test password strength evaluation."""

    def test_weak_password(self):
        """Test weak password detection."""
        strength = get_password_strength("password")

        assert strength['strength'] == 'weak'
        assert strength['length'] == 8
        assert strength['score'] < 40

    def test_medium_password(self):
        """Test medium strength password."""
        strength = get_password_strength("Password123")

        assert strength['strength'] in ['medium', 'strong']
        assert strength['has_upper'] is True
        assert strength['has_lower'] is True
        assert strength['has_digits'] is True

    def test_strong_password(self):
        """Test strong password detection."""
        strength = get_password_strength("MyVery$ecureP@ssw0rd2024!")

        assert strength['strength'] == 'strong'
        assert strength['score'] >= 70
        assert strength['has_upper'] is True
        assert strength['has_lower'] is True
        assert strength['has_digits'] is True
        assert strength['has_special'] is True

    def test_password_length_scoring(self):
        """Test that longer passwords score higher."""
        short = get_password_strength("Pass1!")
        medium = get_password_strength("Password123!")
        long = get_password_strength("VeryLongPassword123!")

        assert short['score'] < medium['score'] < long['score']


class TestPasswordProtectedOperations:
    """Test using password-protected keys for encryption/decryption."""

    def test_encrypt_with_protected_key(self, temp_dir, password_protected_key, test_files):
        """Test encrypting files with a password-protected key."""
        key_path, password, master_key, metadata = password_protected_key
        archive_path = temp_dir / "protected.dxe"

        encrypt_paths(test_files, str(archive_path), master_key)

        assert archive_path.exists()

    def test_decrypt_with_protected_key(self, temp_dir, password_protected_key, test_files):
        """Test full encryption/decryption workflow with protected key."""
        key_path, password, master_key, metadata = password_protected_key
        archive_path = temp_dir / "protected.dxe"
        output_dir = temp_dir / "decrypted"

        # Encrypt
        encrypt_paths(test_files, str(archive_path), master_key)

        # Decrypt
        decrypt_archive(str(archive_path), str(output_dir), master_key)

        assert output_dir.exists()
        assert len(list(output_dir.iterdir())) > 0

    def test_workflow_with_password_file(self, temp_dir, test_files):
        """Test complete workflow using password from file."""
        # Create password file
        password_file = temp_dir / "pw.txt"
        password = "WorkflowPassword123!"
        password_file.write_text(password)

        # Generate protected key
        key_path = temp_dir / "workflow.dxk"
        generate_key_file(str(key_path), password=password)

        # Load key
        master_key, metadata = load_key_file(str(key_path), password=password)

        # Encrypt
        archive_path = temp_dir / "workflow.dxe"
        encrypt_paths(test_files, str(archive_path), master_key)

        # Decrypt
        output_dir = temp_dir / "workflow_out"
        decrypt_archive(str(archive_path), str(output_dir), master_key)

        assert output_dir.exists()


class TestPasswordSecurity:
    """Test password security features."""

    def test_different_salts_for_same_password(self, temp_dir):
        """Test that same password generates different encrypted keys."""
        password = "SamePassword123!"

        # Generate two keys with same password
        key1_path = temp_dir / "key1.dxk"
        key2_path = temp_dir / "key2.dxk"

        generate_key_file(str(key1_path), password=password)
        generate_key_file(str(key2_path), password=password)

        # Read encrypted data
        with open(key1_path, 'rb') as f:
            data1 = f.read()
        with open(key2_path, 'rb') as f:
            data2 = f.read()

        # Encrypted data should be different (different salts)
        assert data1 != data2

    def test_pbkdf2_iterations(self):
        """Test that PBKDF2 uses sufficient iterations."""
        from dextr.key_protection import PASSWORD_ITERATIONS

        # OWASP 2024 recommendation is 600,000 iterations minimum
        assert PASSWORD_ITERATIONS >= 600000
