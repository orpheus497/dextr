"""
tests/conftest.py

Pytest configuration and fixtures for the dextr test suite.
Provides reusable test fixtures for keys, archives, and temporary directories.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Tuple

import pytest

# Import dextr modules for testing
from dextr import decrypt_archive, encrypt_paths, generate_key_file, load_key_file


@pytest.fixture
def temp_dir(tmp_path):
    """
    Provide a temporary directory that's cleaned up after the test.

    Args:
        tmp_path: pytest's built-in tmp_path fixture

    Returns:
        Path to temporary directory
    """
    return tmp_path


@pytest.fixture
def test_key(temp_dir):
    """
    Generate a test encryption key.

    Returns:
        Tuple of (key_path, master_key, metadata)
    """
    key_path = temp_dir / "test_key.dxk"
    metadata = generate_key_file(str(key_path))
    master_key, metadata = load_key_file(str(key_path))
    return str(key_path), master_key, metadata


@pytest.fixture
def password_protected_key(temp_dir):
    """
    Generate a password-protected test key.

    Returns:
        Tuple of (key_path, password, master_key, metadata)
    """
    key_path = temp_dir / "protected_key.dxk"
    password = "TestPassword123!"
    metadata = generate_key_file(str(key_path), password=password)
    master_key, metadata = load_key_file(str(key_path), password=password)
    return str(key_path), password, master_key, metadata


@pytest.fixture
def test_files(temp_dir):
    """
    Create some test files for archiving.

    Returns:
        List of file paths
    """
    files = []

    # Create a simple text file
    file1 = temp_dir / "test1.txt"
    file1.write_text("This is test file 1\nWith multiple lines\n")
    files.append(str(file1))

    # Create a binary file
    file2 = temp_dir / "test2.bin"
    file2.write_bytes(b"\x00\x01\x02\x03\x04\x05" * 100)
    files.append(str(file2))

    # Create a subdirectory with files
    subdir = temp_dir / "subdir"
    subdir.mkdir()
    file3 = subdir / "test3.txt"
    file3.write_text("File in subdirectory\n")
    files.append(str(subdir))

    return files


@pytest.fixture
def test_archive(temp_dir, test_key, test_files):
    """
    Create a test encrypted archive.

    Returns:
        Tuple of (archive_path, key_path, master_key, input_files)
    """
    key_path, master_key, metadata = test_key
    archive_path = temp_dir / "test_archive.dxe"

    encrypt_paths(test_files, str(archive_path), master_key)

    return str(archive_path), key_path, master_key, test_files


@pytest.fixture
def empty_file(temp_dir):
    """
    Create an empty test file.

    Returns:
        Path to empty file
    """
    empty = temp_dir / "empty.txt"
    empty.touch()
    return str(empty)


@pytest.fixture
def large_file(temp_dir):
    """
    Create a large test file (10 MB).

    Returns:
        Path to large file
    """
    large = temp_dir / "large.bin"
    # Write 10 MB of data
    with open(large, "wb") as f:
        for _ in range(10):
            f.write(os.urandom(1024 * 1024))  # 1 MB at a time
    return str(large)


@pytest.fixture
def unicode_filename(temp_dir):
    """
    Create a file with unicode characters in the name.

    Returns:
        Path to unicode filename
    """
    unicode_file = temp_dir / "test_文件_тест_🔒.txt"
    unicode_file.write_text("Unicode filename test\n")
    return str(unicode_file)


@pytest.fixture
def nested_directories(temp_dir):
    """
    Create deeply nested directory structure.

    Returns:
        Path to root of nested structure
    """
    root = temp_dir / "nested"
    current = root
    for i in range(10):
        current = current / f"level_{i}"
        current.mkdir(parents=True, exist_ok=True)
        file = current / f"file_{i}.txt"
        file.write_text(f"File at level {i}\n")
    return str(root)


def assert_files_equal(file1: Path, file2: Path):
    """
    Assert that two files have identical content.

    Args:
        file1: First file path
        file2: Second file path

    Raises:
        AssertionError: If files differ
    """
    assert file1.exists(), f"File {file1} does not exist"
    assert file2.exists(), f"File {file2} does not exist"

    # Compare file sizes first (fast check)
    assert (
        file1.stat().st_size == file2.stat().st_size
    ), f"File sizes differ: {file1.stat().st_size} vs {file2.stat().st_size}"

    # Compare content
    with open(file1, "rb") as f1, open(file2, "rb") as f2:
        chunk_size = 8192
        while True:
            chunk1 = f1.read(chunk_size)
            chunk2 = f2.read(chunk_size)
            assert chunk1 == chunk2, "File contents differ"
            if not chunk1:  # End of file
                break


def assert_directories_equal(dir1: Path, dir2: Path, ignore_permissions: bool = True):
    """
    Assert that two directories have identical structure and content.

    Args:
        dir1: First directory path
        dir2: Second directory path
        ignore_permissions: If True, don't compare file permissions

    Raises:
        AssertionError: If directories differ
    """
    dir1 = Path(dir1)
    dir2 = Path(dir2)

    # Get all files in both directories
    files1 = sorted([p.relative_to(dir1) for p in dir1.rglob("*") if p.is_file()])
    files2 = sorted([p.relative_to(dir2) for p in dir2.rglob("*") if p.is_file()])

    assert files1 == files2, f"Directory structures differ:\n{files1}\nvs\n{files2}"

    # Compare each file
    for rel_path in files1:
        file1 = dir1 / rel_path
        file2 = dir2 / rel_path
        assert_files_equal(file1, file2)
