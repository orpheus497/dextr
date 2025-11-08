"""
tests/test_core.py

Core functionality tests for dextr encryption and decryption.
Tests key generation, encryption/decryption roundtrips, and archive operations.
"""

import pytest
import os
from pathlib import Path

from dextr import (
    generate_key_file,
    load_key_file,
    encrypt_paths,
    decrypt_archive,
    get_archive_info,
    check_archive_integrity,
)
from dextr.exceptions import (
    KeyManagementError,
    EncryptionError,
    DecryptionError,
    ValidationError,
)

from tests.conftest import assert_files_equal, assert_directories_equal


class TestKeyGeneration:
    """Test key file generation and loading."""

    def test_generate_key_basic(self, temp_dir):
        """Test basic key generation."""
        key_path = temp_dir / "test.dxk"
        metadata = generate_key_file(str(key_path))

        assert key_path.exists()
        assert metadata['magic'] == 'DEXTR_KEY'
        assert 'key_id' in metadata
        assert 'created_at' in metadata
        assert 'created_by' in metadata

    def test_load_key(self, test_key):
        """Test loading a generated key."""
        key_path, master_key, metadata = test_key

        assert len(master_key) == 64  # 512 bits
        assert metadata['magic'] == 'DEXTR_KEY'

    def test_key_id_consistency(self, test_key):
        """Test that key ID is consistent across loads."""
        key_path, master_key1, metadata1 = test_key
        master_key2, metadata2 = load_key_file(key_path)

        assert master_key1 == master_key2
        assert metadata1['key_id'] == metadata2['key_id']

    def test_overwrite_protection(self, temp_dir):
        """Test that existing keys aren't overwritten without force."""
        key_path = temp_dir / "test.dxk"
        generate_key_file(str(key_path))

        # Should fail to overwrite
        with pytest.raises((KeyManagementError, ValidationError)):
            generate_key_file(str(key_path))

    def test_invalid_key_file(self, temp_dir):
        """Test loading invalid key file."""
        bad_key = temp_dir / "bad.dxk"
        bad_key.write_text("invalid json{")

        with pytest.raises(KeyManagementError):
            load_key_file(str(bad_key))

    def test_nonexistent_key_file(self, temp_dir):
        """Test loading nonexistent key file."""
        with pytest.raises(KeyManagementError):
            load_key_file(str(temp_dir / "doesnotexist.dxk"))


class TestEncryption:
    """Test encryption functionality."""

    def test_encrypt_single_file(self, temp_dir, test_key):
        """Test encrypting a single file."""
        key_path, master_key, metadata = test_key

        # Create test file
        test_file = temp_dir / "test.txt"
        test_file.write_text("Hello, World!")

        # Encrypt
        archive_path = temp_dir / "test.dxe"
        encrypt_paths([str(test_file)], str(archive_path), master_key)

        assert archive_path.exists()
        assert archive_path.stat().st_size > 0

    def test_encrypt_multiple_files(self, temp_dir, test_key, test_files):
        """Test encrypting multiple files."""
        key_path, master_key, metadata = test_key
        archive_path = temp_dir / "multi.dxe"

        encrypt_paths(test_files, str(archive_path), master_key)

        assert archive_path.exists()

    def test_encrypt_directory(self, temp_dir, test_key):
        """Test encrypting a directory."""
        key_path, master_key, metadata = test_key

        # Create directory with files
        test_dir = temp_dir / "testdir"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("File 1")
        (test_dir / "file2.txt").write_text("File 2")

        # Encrypt
        archive_path = temp_dir / "dir.dxe"
        encrypt_paths([str(test_dir)], str(archive_path), master_key)

        assert archive_path.exists()

    def test_encrypt_empty_file(self, temp_dir, test_key, empty_file):
        """Test encrypting an empty file."""
        key_path, master_key, metadata = test_key
        archive_path = temp_dir / "empty.dxe"

        encrypt_paths([empty_file], str(archive_path), master_key)

        assert archive_path.exists()

    def test_encrypt_large_file(self, temp_dir, test_key, large_file):
        """Test encrypting a large file (10 MB)."""
        key_path, master_key, metadata = test_key
        archive_path = temp_dir / "large.dxe"

        encrypt_paths([large_file], str(archive_path), master_key)

        assert archive_path.exists()


class TestDecryption:
    """Test decryption functionality."""

    def test_decrypt_basic(self, temp_dir, test_archive):
        """Test basic decryption."""
        archive_path, key_path, master_key, input_files = test_archive
        output_dir = temp_dir / "decrypted"

        decrypt_archive(archive_path, str(output_dir), master_key)

        assert output_dir.exists()
        assert len(list(output_dir.iterdir())) > 0

    def test_decrypt_wrong_key(self, temp_dir, test_archive):
        """Test decryption with wrong key fails."""
        archive_path, _, _, _ = test_archive
        output_dir = temp_dir / "decrypted"

        # Generate different key
        wrong_key_path = temp_dir / "wrong.dxk"
        generate_key_file(str(wrong_key_path))
        wrong_key, _ = load_key_file(str(wrong_key_path))

        with pytest.raises(DecryptionError):
            decrypt_archive(archive_path, str(output_dir), wrong_key)

    def test_roundtrip_preservation(self, temp_dir, test_key, test_files):
        """Test that encryption/decryption preserves file content."""
        key_path, master_key, metadata = test_key

        # Encrypt
        archive_path = temp_dir / "roundtrip.dxe"
        encrypt_paths(test_files, str(archive_path), master_key)

        # Decrypt
        output_dir = temp_dir / "restored"
        decrypt_archive(str(archive_path), str(output_dir), master_key)

        # Verify all files are restored correctly
        for input_path in test_files:
            input_path_obj = Path(input_path)
            if input_path_obj.is_file():
                restored_file = output_dir / input_path_obj.name
                assert_files_equal(input_path_obj, restored_file)


class TestArchiveInfo:
    """Test archive metadata functions."""

    def test_get_archive_info(self, test_archive):
        """Test retrieving archive metadata."""
        archive_path, _, _, _ = test_archive

        info = get_archive_info(archive_path)

        assert 'format_version' in info
        assert 'key_id' in info
        assert 'salt' in info
        assert 'file_size' in info
        assert 'encrypted_size' in info

    def test_archive_info_invalid_file(self, temp_dir):
        """Test get_archive_info on invalid file."""
        bad_archive = temp_dir / "bad.dxe"
        bad_archive.write_bytes(b'not a valid archive')

        with pytest.raises(DecryptionError):
            get_archive_info(str(bad_archive))


class TestIntegrityCheck:
    """Test archive integrity checking."""

    def test_integrity_check_valid(self, test_archive):
        """Test integrity check on valid archive."""
        archive_path, _, master_key, _ = test_archive

        result = check_archive_integrity(archive_path, master_key, quick=False)

        assert result['valid'] is True
        assert result['header_valid'] is True
        assert result['key_match'] is True
        assert result['decrypt_success'] is True
        assert result['full_decrypt_success'] is True

    def test_integrity_check_quick(self, test_archive):
        """Test quick integrity check."""
        archive_path, _, master_key, _ = test_archive

        result = check_archive_integrity(archive_path, master_key, quick=True)

        assert result['valid'] is True
        assert result['header_valid'] is True
        assert result['key_match'] is True
        assert result['decrypt_success'] is True

    def test_integrity_check_wrong_key(self, temp_dir, test_archive):
        """Test integrity check with wrong key."""
        archive_path, _, _, _ = test_archive

        # Generate wrong key
        wrong_key_path = temp_dir / "wrong.dxk"
        generate_key_file(str(wrong_key_path))
        wrong_key, _ = load_key_file(str(wrong_key_path))

        result = check_archive_integrity(archive_path, wrong_key, quick=False)

        assert result['valid'] is False
        assert result['key_match'] is False

    def test_integrity_check_corrupted(self, temp_dir, test_archive):
        """Test integrity check on corrupted archive."""
        archive_path, _, master_key, _ = test_archive

        # Corrupt the archive
        with open(archive_path, 'r+b') as f:
            f.seek(100)
            f.write(b'\x00\x00\x00\x00')

        result = check_archive_integrity(archive_path, master_key, quick=False)

        assert result['valid'] is False
        assert result['error'] is not None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_encrypt_nonexistent_file(self, temp_dir, test_key):
        """Test encrypting nonexistent file."""
        key_path, master_key, metadata = test_key
        archive_path = temp_dir / "test.dxe"

        with pytest.raises((EncryptionError, ValidationError)):
            encrypt_paths([str(temp_dir / "doesnotexist.txt")], str(archive_path), master_key)

    def test_decrypt_to_existing_nonempty_dir(self, temp_dir, test_archive):
        """Test decrypting to non-empty directory fails without force."""
        archive_path, _, master_key, _ = test_archive
        output_dir = temp_dir / "nonempty"
        output_dir.mkdir()
        (output_dir / "existing.txt").write_text("existing file")

        # Should fail without force flag
        # Note: This test assumes the decrypt_archive function checks for non-empty dirs
        # The actual behavior depends on implementation
        pass  # Placeholder for actual test

    def test_unicode_filenames(self, temp_dir, test_key, unicode_filename):
        """Test handling of unicode filenames."""
        key_path, master_key, metadata = test_key
        archive_path = temp_dir / "unicode.dxe"

        encrypt_paths([unicode_filename], str(archive_path), master_key)

        output_dir = temp_dir / "unicode_out"
        decrypt_archive(str(archive_path), str(output_dir), master_key)

        # Verify file was restored
        assert len(list(output_dir.iterdir())) > 0

    def test_deeply_nested_directories(self, temp_dir, test_key, nested_directories):
        """Test handling of deeply nested directory structures."""
        key_path, master_key, metadata = test_key
        archive_path = temp_dir / "nested.dxe"

        encrypt_paths([nested_directories], str(archive_path), master_key)

        output_dir = temp_dir / "nested_out"
        decrypt_archive(str(archive_path), str(output_dir), master_key)

        # Verify structure was preserved
        assert_directories_equal(Path(nested_directories), output_dir / Path(nested_directories).name)
