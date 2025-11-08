"""
dextr/streaming.py

Streaming encryption and decryption implementation for the dextr application.
Provides memory-efficient processing of large files through chunked operations.

**EXPERIMENTAL MODULE - NOT YET PRODUCTION-READY**

This module is under active development and is not currently used by the main
dextr application. The streaming decryption implementation (stream_decrypt_layer)
requires optimization before it can be used in production.

TODO: Complete and optimize stream_decrypt_layer chunk boundary detection
TODO: Integrate streaming mode into core.py for large file support
TODO: Add comprehensive tests for streaming operations
TODO: Benchmark and optimize performance

For now, use the standard (non-streaming) encrypt_paths() and decrypt_archive()
functions from dextr.core for all operations.
"""

import os
import struct
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from dextr.exceptions import ValidationError
from dextr.logging_config import get_logger
from dextr.validation import sanitize_archive_member

logger = get_logger(__name__)


# Constants
NONCE_SIZE = 12
DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB


class StreamingError(Exception):
    """Errors related to streaming operations."""

    pass


def chunked_read(file_obj: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    """
    Read a file in chunks.

    Args:
        file_obj: File object to read from
        chunk_size: Size of each chunk in bytes

    Yields:
        Chunks of data
    """
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        yield chunk


def stream_encrypt_layer(
    input_stream: Iterator[bytes],
    cipher,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> Iterator[bytes]:
    """
    Encrypt a stream of data with a single encryption layer.

    Each chunk is encrypted independently with its own nonce.

    Args:
        input_stream: Iterator yielding plaintext chunks
        cipher: Cipher instance (ChaCha20Poly1305 or AESGCM)
        chunk_size: Size of chunks to process
        progress_callback: Optional callback for progress updates

    Yields:
        Encrypted chunks (each prefixed with its nonce)
    """
    bytes_processed = 0

    for chunk in input_stream:
        # Generate unique nonce for this chunk
        nonce = os.urandom(NONCE_SIZE)

        # Encrypt chunk
        try:
            encrypted_chunk = cipher.encrypt(nonce, chunk, None)
        except Exception as e:
            raise StreamingError(f"Encryption failed: {e}") from e

        # Yield nonce + encrypted data
        yield nonce + encrypted_chunk

        # Update progress
        bytes_processed += len(chunk)
        if progress_callback:
            progress_callback(bytes_processed)


def stream_decrypt_layer(
    input_stream: Iterator[bytes],
    cipher,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> Iterator[bytes]:
    """
    Decrypt a stream of data from a single encryption layer.

    Each chunk must be prefixed with its nonce.

    Args:
        input_stream: Iterator yielding encrypted chunks (with nonces)
        cipher: Cipher instance (ChaCha20Poly1305 or AESGCM)
        chunk_size: Size of chunks to process
        progress_callback: Optional callback for progress updates

    Yields:
        Decrypted chunks
    """
    bytes_processed = 0
    buffer = b""

    for chunk in input_stream:
        buffer += chunk

        # Process complete encrypted chunks from buffer
        while len(buffer) >= NONCE_SIZE:
            # We don't know the exact size of encrypted chunks due to authentication tags
            # For ChaCha20Poly1305 and AES-GCM, tag is 16 bytes
            # Try to decrypt what we have
            try:
                nonce = buffer[:NONCE_SIZE]
                # Estimate encrypted chunk size (original + 16 byte tag)
                # We'll try to decrypt progressively
                min_size = NONCE_SIZE + 16  # nonce + minimum tag

                if len(buffer) < min_size:
                    break  # Need more data

                # Try different chunk sizes to find the right boundary
                # This is needed because we don't store chunk sizes explicitly
                # Start with expected size and work backwards
                max_try_size = min(len(buffer) - NONCE_SIZE, chunk_size + 1024)

                decrypted = None
                encrypted_size = 0

                for try_size in range(max_try_size, 15, -1):  # Minimum 16 bytes for tag
                    if try_size + NONCE_SIZE > len(buffer):
                        continue

                    try:
                        encrypted_data = buffer[NONCE_SIZE : NONCE_SIZE + try_size]
                        decrypted = cipher.decrypt(nonce, encrypted_data, None)
                        encrypted_size = try_size
                        break  # Successfully decrypted
                    except InvalidTag:
                        continue  # Wrong size, try smaller

                if decrypted is None:
                    # Couldn't decrypt with current buffer, need more data
                    break

                # Successfully decrypted chunk
                yield decrypted

                # Remove processed data from buffer
                buffer = buffer[NONCE_SIZE + encrypted_size :]

                # Update progress
                bytes_processed += len(decrypted)
                if progress_callback:
                    progress_callback(bytes_processed)

            except Exception as e:
                raise StreamingError(f"Decryption failed: {e}") from e

    # Check if there's leftover data that couldn't be decrypted
    if len(buffer) > 0:
        raise StreamingError(f"Incomplete encrypted data in stream ({len(buffer)} bytes remaining)")


def compress_stream(
    input_stream: Iterator[bytes],
    level: int = 9,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> Iterator[bytes]:
    """
    Compress a stream of data using zlib.

    Args:
        input_stream: Iterator yielding uncompressed data
        level: Compression level (1-9)
        progress_callback: Optional callback for progress updates

    Yields:
        Compressed data chunks
    """
    compressor = zlib.compressobj(level=level)
    bytes_processed = 0

    for chunk in input_stream:
        compressed = compressor.compress(chunk)
        if compressed:
            yield compressed

        bytes_processed += len(chunk)
        if progress_callback:
            progress_callback(bytes_processed)

    # Flush remaining data
    final = compressor.flush()
    if final:
        yield final


def decompress_stream(
    input_stream: Iterator[bytes], progress_callback: Optional[Callable[[int], None]] = None
) -> Iterator[bytes]:
    """
    Decompress a stream of data using zlib.

    Args:
        input_stream: Iterator yielding compressed data
        progress_callback: Optional callback for progress updates

    Yields:
        Decompressed data chunks
    """
    decompressor = zlib.decompressobj()
    bytes_processed = 0

    try:
        for chunk in input_stream:
            decompressed = decompressor.decompress(chunk)
            if decompressed:
                yield decompressed

            bytes_processed += len(chunk)
            if progress_callback:
                progress_callback(bytes_processed)

        # Flush remaining data
        final = decompressor.flush()
        if final:
            yield final

    except zlib.error as e:
        raise StreamingError(f"Decompression failed: {e}") from e


def write_stream_to_file(stream: Iterator[bytes], output_path: Path) -> int:
    """
    Write a stream to a file.

    Args:
        stream: Iterator yielding data chunks
        output_path: Path to output file

    Returns:
        Total bytes written
    """
    total_bytes = 0

    try:
        with open(output_path, "wb") as f:
            for chunk in stream:
                f.write(chunk)
                total_bytes += len(chunk)
    except IOError as e:
        raise StreamingError(f"Failed to write to file: {e}") from e

    return total_bytes


def read_file_stream(input_path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    """
    Create a stream from a file.

    Args:
        input_path: Path to input file
        chunk_size: Size of chunks to read

    Yields:
        File data chunks
    """
    try:
        with open(input_path, "rb") as f:
            yield from chunked_read(f, chunk_size)
    except IOError as e:
        raise StreamingError(f"Failed to read file: {e}") from e


def create_tar_to_stream(
    paths: List[Path], progress_callback: Optional[Callable[[int], None]] = None
) -> Iterator[bytes]:
    """
    Create a tar.xz archive and stream it.

    This creates a temporary tar.xz file and streams it out.
    For true streaming, we'd need to use tarfile in stream mode,
    but tar.xz compression requires the full file.

    Args:
        paths: List of paths to archive
        progress_callback: Optional callback for progress updates

    Yields:
        Archive data chunks
    """
    temp_fd = None
    temp_path = None

    try:
        # Create temporary tar.xz file
        temp_fd, temp_path = tempfile.mkstemp(suffix=".tar.xz")

        # Create archive
        with tarfile.open(fileobj=os.fdopen(temp_fd, "wb"), mode="w:xz") as tar:
            for path in paths:
                tar.add(path, arcname=os.path.basename(str(path)))
                logger.debug(f"Added to archive: {path}")

        # Stream the archive file
        yield from read_file_stream(Path(temp_path))

    except Exception as e:
        raise StreamingError(f"Failed to create tar archive: {e}") from e

    finally:
        # Clean up temporary file
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as e:
                logger.warning(f"Failed to remove temporary file {temp_path}: {e}")


def extract_tar_from_stream(
    stream: Iterator[bytes],
    output_dir: Path,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> None:
    """
    Extract a tar.xz archive from a stream.

    This writes the stream to a temporary file and then extracts it.
    For true streaming extraction, we'd need special handling,
    but tar.xz decompression works best with a complete file.

    Args:
        stream: Iterator yielding archive data
        output_dir: Directory to extract to
        progress_callback: Optional callback for progress updates
    """
    temp_fd = None
    temp_path = None

    try:
        # Write stream to temporary file
        temp_fd, temp_path = tempfile.mkstemp(suffix=".tar.xz")

        with os.fdopen(temp_fd, "wb") as f:
            bytes_written = 0
            for chunk in stream:
                f.write(chunk)
                bytes_written += len(chunk)
                if progress_callback:
                    progress_callback(bytes_written)

        # Extract archive with path validation
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

            logger.debug(f"Extracted {len(members_to_extract)} items to {output_dir}")

    except tarfile.TarError as e:
        raise StreamingError(f"Failed to extract tar archive: {e}") from e
    except Exception as e:
        raise StreamingError(f"Failed to process archive stream: {e}") from e

    finally:
        # Clean up temporary file
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as e:
                logger.warning(f"Failed to remove temporary file {temp_path}: {e}")


def get_file_size(path: Path) -> int:
    """
    Get the size of a file in bytes.

    Args:
        path: Path to file

    Returns:
        File size in bytes
    """
    try:
        return path.stat().st_size
    except OSError as e:
        raise StreamingError(f"Failed to get file size: {e}") from e
