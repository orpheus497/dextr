# Getting Started with dextr

Welcome to dextr - a secure archiving and encryption system that protects your files with military-grade encryption.

## What is dextr?

dextr encrypts your files and folders into secure archives that can only be opened with your unique key file. It's like a password-protected zip file, but with:

- **Much stronger encryption** (4 layers of military-grade protection)
- **Better compression** (tar.xz + zlib)
- **Automatic tampering detection** (nobody can modify your encrypted files without you knowing)
- **Portable keys** (one key file can encrypt unlimited archives)

## Installation

### Step 1: Choose Your Platform

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
1. Check if Python 3.7+ is installed
2. Install the cryptography library
3. Optionally install dextr as a system command
4. Test that everything works

### Step 2: Follow the Prompts

The installer will ask you to choose:
- **Option 1**: System-wide (dextr works from any directory)
- **Option 2**: User-only (no admin needed, recommended)
- **Option 3**: Development mode (for customizing)
- **Option 4**: Skip (just install dependencies, use ./run.sh)

**Recommendation**: Choose Option 2 for most users.

## Your First Encryption

Let's encrypt a file in 3 simple steps:

### Step 1: Create a Key

```bash
dextr generate
```

This creates `dextrkey.dxk` - your master encryption key.

**IMPORTANT**: Back up this file! Without it, you cannot decrypt your data.

### Step 2: Encrypt Something

```bash
dextr encrypt -k dextrkey.dxk -i myfile.txt -o encrypted.dxe
```

This creates `encrypted.dxe` - your encrypted archive.

You can now:
- Email the `.dxe` file (safe without the key)
- Upload to cloud storage
- Transfer via USB
- Store as backup

### Step 3: Decrypt When Needed

```bash
dextr decrypt -k dextrkey.dxk -i encrypted.dxe -o restored/
```

Your original file is now in the `restored/` directory.

## Common Tasks

### Encrypt Multiple Files

```bash
dextr encrypt -k mykey.dxk -i file1.txt file2.pdf photos/ -o backup.dxe
```

All files and folders get packed into one encrypted archive.

### Encrypt an Entire Folder

```bash
dextr encrypt -k mykey.dxk -i ~/Documents -o documents_backup.dxe
```

### View Key Information

```bash
dextr info -k mykey.dxk
```

Shows when the key was created, by whom, and its unique ID.

### Quiet Mode (for Scripts)

```bash
dextr encrypt -k mykey.dxk -i data/ -o backup.dxe --quiet
```

Suppresses status messages, only shows errors.

## Understanding Key Files

Your `.dxk` key file contains:
- A 512-bit random master key
- Creation timestamp
- Creator name
- Unique key ID

**Key Safety Tips:**
1. **Back it up** - Copy to USB drive, cloud storage (separate from encrypted files)
2. **Never share** - Treat like a password
3. **Use different keys** - Personal files, work files, etc.
4. **Test it** - After creating backup, try decrypting to make sure key works

## Understanding Encrypted Files

Your `.dxe` encrypted archives contain:
- All your files compressed and encrypted
- Metadata (file names, timestamps, permissions)
- Authentication tags (to detect tampering)

**Archive Properties:**
- **Safe to share** (without the key, nobody can decrypt)
- **Tamper-evident** (any modification is detected)
- **Compressed** (usually smaller than original)
- **Self-contained** (everything in one file)

## Security Model

### What protects your files?

1. **Master Key**: 512-bit random key (astronomically hard to guess)
2. **Unique Salts**: Every archive gets a unique random value
3. **Key Derivation**: HKDF algorithm creates 4 unique keys per archive
4. **Layered Encryption**: 4 independent encryption algorithms
5. **Authentication**: Any tampering is automatically detected

### What dextr does NOT do:

- ❌ Store your files online
- ❌ Send data anywhere
- ❌ Connect to the internet
- ❌ Track what you encrypt
- ❌ Have backdoors or master keys

Everything runs locally on your computer.

## Getting Help

### Built-in Help System

```bash
dextr help                      # General help
dextr help security             # Encryption details
dextr help workflow             # Common workflows
dextr help examples             # Command examples
dextr help troubleshooting      # Fix common problems
```

### Command-Specific Help

```bash
dextr encrypt --help            # Encryption options
dextr decrypt --help            # Decryption options
```

### Documentation Files

- `README.md` - Full technical documentation
- `USAGE.md` - Quick reference guide
- `CHANGELOG.md` - Version history

## Troubleshooting Quick Fixes

**Problem**: "Command 'dextr' not found"
```bash
# Use direct execution instead:
./run.sh [command]
# or
python3 dextr.py [command]
```

**Problem**: "Key mismatch error"
- You're using the wrong key file
- Use the same key that encrypted the archive

**Problem**: "Output file already exists"
- Add `--force` flag to overwrite
- Or choose a different filename

**Problem**: "Permission denied"
- Check file permissions
- Make sure you own the files
- On Linux: `chmod +x install.sh run.sh`

## Example Workflows

### Weekly Backup

```bash
# Sunday night backup script
dextr encrypt -k ~/.backup_key.dxk \
  -i ~/Documents ~/Photos \
  -o ~/Backups/backup_$(date +%Y%m%d).dxe \
  --quiet
```

### Secure File Sharing

```bash
# 1. Create shared key (give to recipient securely)
dextr generate shared_key.dxk

# 2. Encrypt files
dextr encrypt -k shared_key.dxk -i confidential/ -o transfer.dxe

# 3. Send .dxe file by email (safe without key)
# 4. Recipient decrypts with their copy of the key
dextr decrypt -k shared_key.dxk -i transfer.dxe -o received/
```

### Encrypting Before Cloud Upload

```bash
# Encrypt before uploading to Dropbox/Google Drive
dextr encrypt -k personal.dxk -i ~/Private -o ~/Dropbox/private_backup.dxe

# Download and decrypt when needed
dextr decrypt -k personal.dxk -i ~/Dropbox/private_backup.dxe -o ~/Private_Restored
```

## Next Steps

1. **Test the basics**: Generate a key, encrypt a test file, decrypt it
2. **Set up backups**: Create a backup key and test your workflow
3. **Read the full guide**: `cat README.md` for technical details
4. **Explore help topics**: `dextr help` for advanced features

## Support

dextr is free, open-source software. For issues:
1. Check `dextr help troubleshooting`
2. Read the full README.md
3. Review command syntax with `--help` flags

## License

dextr uses the cryptography library (Apache-2.0 / BSD license).
Created by orpheus497.

---

**Remember**: Your key file is like a house key - protect it, back it up, and never lose it!
