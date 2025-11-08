# Dextr Examples

This directory contains practical examples demonstrating how to use the dextr library and CLI for secure archiving and encryption.

## Prerequisites

Install dextr:
```bash
pip install dextr
```

Or install from source:
```bash
git clone https://github.com/orpheus497/dextr.git
cd dextr
pip install -e .
```

## Example Scripts

### 1. Basic Encryption (`basic_encryption.py`)

Simple example showing how to:
- Generate an encryption key
- Encrypt a file or directory
- Decrypt an archive
- Check archive integrity

**Usage:**
```bash
python examples/basic_encryption.py
```

### 2. Batch Encryption (`batch_encryption.py`)

Demonstrates encrypting multiple files and directories in one operation.

**Usage:**
```bash
python examples/batch_encryption.py
```

### 3. Automated Backup (`automated_backup.py`)

Production-ready backup script with:
- Automatic archive naming with timestamps
- Configurable backup directory
- Optional compression
- Integrity verification

**Usage:**
```bash
# Basic backup
python examples/automated_backup.py /path/to/backup

# With custom output directory
python examples/automated_backup.py /path/to/backup --output /backups

# With password protection
python examples/automated_backup.py /path/to/backup --password
```

### 4. Secure Transfer (`secure_transfer.py`)

Example for securely sharing files:
- Generate one-time encryption key
- Create encrypted archive
- Export key securely
- Import key and decrypt

**Usage:**
```bash
# Sender side
python examples/secure_transfer.py send /path/to/files

# Receiver side
python examples/secure_transfer.py receive archive.dxe
```

### 5. Progress Tracking (`progress_tracking.py`)

Demonstrates custom progress callbacks for integration into larger applications.

**Usage:**
```bash
python examples/progress_tracking.py
```

## CLI Examples

### Generate Key File
```bash
# Standard key
python -m dextr generate mykey.dxk

# Password-protected key
python -m dextr generate mykey.dxk --password
```

### Encrypt Files
```bash
# Single file
python -m dextr encrypt -k mykey.dxk -i document.pdf -o document.dxe

# Multiple files
python -m dextr encrypt -k mykey.dxk -i file1.txt file2.pdf dir/ -o archive.dxe

# With password-protected key
python -m dextr encrypt -k mykey.dxk --password -i files/ -o archive.dxe
```

### Decrypt Archives
```bash
# Standard decryption
python -m dextr decrypt -k mykey.dxk -i archive.dxe -o restored/

# With password
python -m dextr decrypt -k mykey.dxk --password -i archive.dxe -o restored/
```

### Check Archive Integrity
```bash
# Quick check (first layer only)
python -m dextr check -k mykey.dxk -i archive.dxe

# Full validation (all layers)
python -m dextr check -k mykey.dxk -i archive.dxe --full
```

### Archive Information
```bash
# View archive metadata
python -m dextr info -i archive.dxe

# List contents
python -m dextr list -k mykey.dxk -i archive.dxe
```

## Cross-Platform Notes

All examples work on:
- **Linux** (all distributions)
- **macOS** (Terminal)
- **Windows** (Command Prompt, PowerShell, WSL)
- **Termux** (Android)

### Windows-Specific Notes

On Windows, use Python instead of python3:
```cmd
python -m dextr generate mykey.dxk
python examples\basic_encryption.py
```

### Termux-Specific Notes

Install dependencies on Termux:
```bash
pkg install python
pip install dextr
```

## Security Best Practices

1. **Key Storage**: Store key files securely with proper permissions (600)
2. **Password Protection**: Use strong passwords (16+ characters, mixed case, symbols)
3. **Backup Keys**: Keep encrypted backups of key files in separate locations
4. **Verify Integrity**: Always run integrity checks on important archives
5. **Secure Deletion**: Use secure deletion tools for plaintext after encryption

## Support

For issues or questions:
- GitHub Issues: https://github.com/orpheus497/dextr/issues
- Documentation: https://github.com/orpheus497/dextr
