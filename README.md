# dextr - Secure Archiving & Encryption System

**Original Concept by orpheus497**

`dextr` is a command-line tool that provides robust, multi-layered, and authenticated file encryption. It can securely archive multiple files and folders into a single encrypted `.dxe` file, making it ideal for backups and secure data transfer.

It uses a portable key file-based system, offering a secure alternative to passwords. A single, securely-stored key file can be used to encrypt and decrypt any number of archives.

```
╔══════════════════════════════════════════════════╗
║              D E X T R  v1.3.0                   ║
║      Secure Archiving & Encryption System        ║
║            Created by orpheus497                 ║
╚══════════════════════════════════════════════════╝
```

## ⚡ Quick Install

**Never used dextr before?** Start with [GETTING_STARTED.md](GETTING_STARTED.md) for a friendly introduction.

### Automated Installation (Recommended)

**Linux/macOS/Termux:**
```bash
chmod +x install.sh
./install.sh
```

**Windows:**
```batch
install.bat
```

The installer will:
- Check system requirements
- Install dependencies automatically
- Set up dextr command (optional)
- Verify everything works

**That's it!** The installer guides you through everything.

## 🔑 Core Features

- **Secure Archiving**: Group multiple files and folders into a single encrypted archive.
- **High-Ratio Compression**: Uses a `.tar.xz` (LZMA) archive format for high compression ratios, followed by a second `zlib` compression layer.
- **Secure Key Derivation**: Employs HKDF-SHA256 to derive unique encryption keys for every archive, based on a 512-bit master key and a random salt.
- **Five Layers of Defense**: Provides defense-in-depth with a sequence of LZMA archiving, zlib compression, ChaCha20-Poly1305, and AES-256-GCM encryption.
- **Authenticated Encryption**: Every cryptographic layer is an AEAD (Authenticated Encryption with Associated Data) cipher, which automatically detects tampering, corruption, or authentication failures.
- **Command-Line Interface**: A clean, scriptable CLI for generating keys, creating encrypted archives, and extracting them.
- **Python Library API**: Full programmatic access to all encryption functionality for integration into Python applications.

## 🏗️ Security Architecture

`dextr` secures files by processing them through a multi-stage pipeline. The cryptographic keys for the encryption layers are uniquely generated for each archive using the industry-standard **HKDF** key derivation function.

```
Your Files/Folders ──► 1. Archive Creation (.tar.xz using LZMA)
                           │
                           ▼
                     2. zlib Compression
                           │
                           ▼
      ┌───────────────────────────────────────────┐
      │             ENCRYPTION GAUNTLET           │
      │                                           │
      │   ┌────────────┐   ┌────────────┐         │
      ├───►  ChaCha20  ├───►   AES-GCM  ├───┐     │
      │   └────────────┘   └────────────┘   │     │
      │         ▲                ▲          │     │
      │         │                │          ▼     │
      │   ┌────────────┐   ┌────────────┐   │     │
      └───┤   AES-GCM  │◄───┤  ChaCha20  │◄──┘    │
          └────────────┘   └────────────┘         │
      └───────────────────────────────────────────┘
                           │
                           ▼
                  Encrypted Archive (.dxe)
```

1.  **Archiving (LZMA)**: Your input files and folders are bundled into a single `.tar.xz` archive, which uses the LZMA algorithm for high-efficiency compression.
2.  **Compression (zlib)**: The entire `.tar.xz` archive is then compressed again using `zlib`. This can sometimes find additional compressible patterns in the archive metadata itself.
3.  **Key Derivation**: A unique 32-byte salt is generated. This salt, combined with your 512-bit master key, is fed into HKDF-SHA256 to produce four independent 256-bit keys for the cryptographic layers.
4.  **Encryption Gauntlet**: The compressed data passes through four layers of authenticated encryption: ChaCha20 -> AES-GCM -> ChaCha20 -> AES-GCM.

## 📦 Installation

### Requirements
- Python 3.8 or higher
- The `cryptography` library (automatically installed)

### Option 1: Install with pip (Recommended)

This installs `dextr` as a system command available everywhere:

```bash
# Clone or download the repository
cd dextr

# Install for current user only
pip install --user .

# Or install system-wide (may require sudo/admin)
pip install .
```

After installation, you can run `dextr` from anywhere:
```bash
dextr --help
```

### Option 2: Run Directly (No Installation)

#### On Linux, macOS, and Termux:

```bash
# Install dependencies
pip install --user -r requirements.txt

# Make executable (first time only)
chmod +x run.sh

# Run dextr
./run.sh --help

# Or run directly with Python
python3 dextr.py --help
```

#### On Windows:

```batch
REM Install dependencies
pip install -r requirements.txt

REM Run dextr
run.bat --help

REM Or run directly with Python
python dextr.py --help
```

### Option 3: Development Mode

Install in editable mode to work on the code:

```bash
pip install -e .
```

### Platform-Specific Notes

**Linux/macOS/Termux:**
- Use `python3` and `pip3` if `python` points to Python 2.x
- On Termux: `pkg install python` installs Python 3.x by default

**Windows:**
- Use `py -3` if you have multiple Python versions
- The `run.bat` script automatically finds your Python installation

**All Platforms:**
- Ensure Python 3.7+ is in your PATH
- Use `--user` flag with pip if you don't have admin privileges

## 🚀 Quick Start Guide

**Note:** These examples assume you've installed dextr with pip. If running directly, replace `dextr` with `python3 dextr.py` (Linux/macOS/Termux) or `python dextr.py` (Windows).

### Step 1: Generate Your Master Key

Create a new key file. The default name is `dextrkey.dxk`.

```bash
$ dextr generate

Success: Generated new key file at 'dextrkey.dxk'
... (metadata will be printed here)
```

### Step 2: Create an Encrypted Archive

Archive and encrypt a folder named `project_files` and a separate file `notes.txt` into a single output file `backup.dxe`.

```bash
$ dextr encrypt -k dextrkey.dxk -i ./project_files notes.txt -o backup.dxe

[*] Loading key from 'dextrkey.dxk'...
[*] Archiving and encrypting 2 path(s)...
Success: Archive encrypted to 'backup.dxe'
    Encrypted size: 1,234,567 bytes
```

### Step 3: Decrypt and Extract an Archive

Decrypt `backup.dxe` and extract its contents into a new directory named `restored_backup`.

```bash
$ dextr decrypt -k dextrkey.dxk -i backup.dxe -o ./restored_backup

[*] Loading key from 'dextrkey.dxk'...
[*] Decrypting and extracting 'backup.dxe'...
Success: Archive decrypted and extracted to './restored_backup'
```

## 📖 CLI Usage

**Note:** If you installed with pip, use `dextr` command. If running directly, use `python3 dextr.py` (or `python dextr.py` on Windows).

### `generate`

Generates a new key file.

```bash
# Generate a key with the default name (dextrkey.dxk)
dextr generate

# Generate a key with a specific name
dextr generate path/to/my_key.dxk
```

### `encrypt`

Archives and encrypts one or more files/folders into a single `.dxe` file.

```bash
dextr encrypt -k <key_path> -i <path1> [<path2> ...] -o <output_archive.dxe>

# Example: Encrypt a single directory
dextr encrypt -k dextrkey.dxk -i ./my_photos -o photos.dxe

# Example: Encrypt multiple files and a directory
dextr encrypt -k dextrkey.dxk -i file1.pdf file2.docx ./work_docs -o archive.dxe
```

### `decrypt`

Decrypts a `.dxe` file and extracts its contents to a specified directory.

```bash
dextr decrypt -k <key_path> -i <archive.dxe> -o <output_directory>

# Example
dextr decrypt -k dextrkey.dxk -i archive.dxe -o ./restored_files
```

### `info`

Displays metadata from a key file.

```bash
dextr info --key dextrkey.dxk
```

## 🐍 Using dextr as a Python Library

In addition to the command-line interface, dextr can be imported and used programmatically in your Python applications.

### Installation for Library Use

```bash
pip install .
# or
pip install --user .
```

### Basic Library Usage

```python
from dextr import (
    generate_key_file,
    load_key_file,
    encrypt_paths,
    decrypt_archive,
    DextrError,
    KeyManagementError,
    ArchivingError,
    EncryptionError,
    DecryptionError,
    ValidationError
)

# Generate a new key file
try:
    metadata = generate_key_file('mykey.dxk')
    print(f"Created key: {metadata['key_id']}")
except KeyManagementError as e:
    print(f"Error: {e}")

# Load an existing key
master_key, metadata = load_key_file('mykey.dxk')
print(f"Loaded key created by: {metadata['created_by']}")

# Encrypt files
try:
    encrypt_paths(
        ['document.pdf', 'photos/', 'data.txt'],
        'backup.dxe',
        master_key
    )
    print("Encryption successful")
except (ValidationError, ArchivingError, EncryptionError) as e:
    print(f"Encryption failed: {e}")

# Decrypt archive
try:
    decrypt_archive('backup.dxe', 'restored/', master_key)
    print("Decryption successful")
except DecryptionError as e:
    print(f"Decryption failed: {e}")
```

### Available Functions

- **`generate_key_file(path: str, username: str = None) -> Dict[str, Any]`**
  Generates a new 512-bit master key and saves it to the specified path.

- **`load_key_file(path: str) -> Tuple[bytes, Dict[str, Any]]`**
  Loads and validates a key file, returning the master key and metadata.

- **`encrypt_paths(in_paths: List[str], out_path: str, master_key: bytes) -> None`**
  Encrypts one or more files/directories into a single encrypted archive.

- **`decrypt_archive(in_path: str, out_dir: str, master_key: bytes) -> None`**
  Decrypts an archive and extracts its contents to a directory.

### Exception Hierarchy

All dextr exceptions inherit from `DextrError`:

- **`KeyManagementError`**: Issues with key file operations
- **`ArchivingError`**: Problems during file archiving
- **`EncryptionError`**: Failures during encryption
- **`DecryptionError`**: Failures during decryption (wrong key, corrupted data, etc.)

### Constants

- **`MAGIC_HEADER`**: Magic bytes for .dxe files (`b'DEXTR'`)
- **`FORMAT_VERSION`**: Current file format version
- **`KEY_FILE_MAGIC`**: Magic string for .dxk files
- **`MASTER_KEY_SIZE`**: Size of master key in bytes (64 = 512 bits)

## 🛡️ Security Best Practices

- **BACK UP YOUR KEY FILE**: Keep multiple copies of your `.dxk` file in separate, secure locations. **If you lose the key file, your data is irrecoverable.**
- **SEPARATE KEYS AND DATA**: Do not store your key file in the same cloud folder or on the same drive as your encrypted files.
- **USE MULTIPLE KEYS**: Consider using different key files for different categories of data (e.g., `personal.dxk`, `work.dxk`).

## 🙏 Credits & License

- **Original Concept & Design**: orpheus497
- **Core Cryptography**: The [cryptography](https://github.com/pyca/cryptography) library, which is licensed under the dual Apache-2.0 and BSD licenses.
- **Progress Display**: The [tqdm](https://github.com/tqdm/tqdm) library, which is licensed under the MIT License or Mozilla Public License 2.0.
- **TOML Parsing** (Python < 3.11): The [tomli](https://github.com/hukkin/tomli) library, which is licensed under the MIT License.

This project is provided as-is. While it is built with modern, secure cryptographic primitives, no warranty is provided. Always maintain backups of your original data.
