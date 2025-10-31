# Quick Reference Guide for dextr

## Installation Methods

### Method 1: pip install (Recommended)
```bash
pip install --user .
# Then use: dextr [command]
```

### Method 2: Direct execution
**Linux/macOS/Termux:**
```bash
./run.sh [command]
# or
python3 dextr.py [command]
```

**Windows:**
```batch
run.bat [command]
REM or
python dextr.py [command]
```

## Common Commands

### Generate a key file
```bash
dextr generate                    # Creates dextrkey.dxk
dextr generate mykey.dxk          # Custom filename
```

### Encrypt files
```bash
# Single file
dextr encrypt -k mykey.dxk -i file.txt -o backup.dxe

# Multiple files
dextr encrypt -k mykey.dxk -i file1.txt file2.pdf -o backup.dxe

# Directory
dextr encrypt -k mykey.dxk -i ./my_folder -o backup.dxe

# Mixed (files + directories)
dextr encrypt -k mykey.dxk -i file.txt ./folder1 ./folder2 -o backup.dxe
```

### Decrypt archives
```bash
dextr decrypt -k mykey.dxk -i backup.dxe -o ./restored
```

### View key information
```bash
dextr info -k mykey.dxk
```

## Optional Flags

### --force
Skip confirmation prompts, overwrite existing files:
```bash
dextr generate mykey.dxk --force
dextr encrypt -k key.dxk -i file.txt -o backup.dxe --force
```

### --quiet
Suppress status messages (useful for scripts):
```bash
dextr encrypt -k key.dxk -i file.txt -o backup.dxe --quiet
```

### --verbose
Show detailed progress information:
```bash
dextr encrypt -k key.dxk -i file.txt -o backup.dxe --verbose
```

## Platform-Specific Tips

### Linux/macOS
- Make scripts executable: `chmod +x run.sh dextr.py`
- Use `python3` explicitly if `python` is Python 2.x
- Install for user only: `pip install --user .`

### Windows
- Use `py -3` for Python 3.x if needed
- `run.bat` automatically finds Python
- May need admin privileges for system-wide install

### Termux (Android)
- Install Python: `pkg install python`
- Install dependencies: `pip install -r requirements.txt`
- Everything else works like Linux

## Security Best Practices

1. **Back up your key files** - Store copies in multiple secure locations
2. **Keep keys separate from data** - Don't store keys with encrypted archives
3. **Use different keys** for different purposes (work, personal, etc.)
4. **Test decryption** after creating archives to verify they work
5. **Secure delete original files** after successful encryption if needed

## Troubleshooting

### "Python not found"
- Ensure Python 3.7+ is installed and in PATH
- Try `python3` or `py -3` explicitly

### "ModuleNotFoundError: No module named 'cryptography'"
```bash
pip install --user cryptography
```

### "Permission denied" on Linux/macOS
```bash
chmod +x run.sh dextr.py
```

### "Key mismatch" error on decrypt
- You're using the wrong key file
- Use the same key that was used to encrypt

### Import errors after pip install
- Restart your terminal/shell
- Check `~/.local/bin` is in PATH (Linux/macOS)

## Examples

### Backup important documents
```bash
dextr generate backup_key.dxk
dextr encrypt -k backup_key.dxk -i ~/Documents ~/Photos -o backup_$(date +%Y%m%d).dxe
```

### Restore a backup
```bash
dextr decrypt -k backup_key.dxk -i backup_20251031.dxe -o ~/restored
```

### Check what key you have
```bash
dextr info -k mykey.dxk
```

### Quiet operation for scripts
```bash
dextr encrypt -k key.dxk -i data/ -o backup.dxe --quiet && echo "Backup complete"
```
