# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The dextr team takes security bugs seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**DO NOT** file a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by creating a private security advisory on GitHub or by contacting the project maintainer directly.

### What to Include

When reporting a vulnerability, please include:

1. **Description**: Clear description of the vulnerability
2. **Impact**: What an attacker could achieve
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Proof of Concept**: If possible, include a minimal PoC
5. **Suggested Fix**: If you have ideas on how to fix it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium/Low: 30-90 days

### Security Best Practices

When using dextr:

1. **Key Management**
   - Store key files (.dxk) in secure locations
   - Never commit key files to version control
   - Use different keys for different purposes
   - Back up keys in multiple secure locations
   - Set restrictive file permissions (0600 on Unix)

2. **File Handling**
   - Verify archive integrity after creation
   - Test decryption before destroying original files
   - Use secure channels to transfer keys
   - Never send keys and encrypted files together

3. **System Security**
   - Keep dextr and dependencies up to date
   - Use the latest Python version supported
   - Monitor for security advisories
   - Run in isolated environments when possible

4. **Operational Security**
   - Enable logging for audit trails
   - Monitor for unusual activity
   - Implement access controls
   - Regular security audits

## Known Limitations

### Out of Scope

The following are considered out of scope:

1. **Social Engineering**: Tricking users into revealing keys
2. **Physical Access**: Attacks requiring physical machine access
3. **Side Channel**: Timing attacks, power analysis (relies on cryptography library)
4. **Denial of Service**: Resource exhaustion from large files
5. **Key Compromise**: Security after key file is compromised

### Security Assumptions

dextr's security depends on:

1. **Secure Random Number Generation**: OS-provided randomness (os.urandom)
2. **Cryptographic Library**: The `cryptography` library is secure and properly implemented
3. **Key Secrecy**: Master keys remain confidential
4. **No Memory Dumps**: Adversary cannot access process memory
5. **File System Security**: Operating system protects file permissions

## Security Features

### Implemented

- Multi-layer authenticated encryption (AEAD)
- HKDF key derivation with unique salts
- Path traversal protection
- Archive member validation
- Key file permission enforcement
- Atomic file operations
- Comprehensive input validation
- Security event logging

### Roadmap

Future security enhancements may include:

- Key rotation mechanism
- Encrypted key storage (password-protected)
- Secure memory handling
- Hardware security module (HSM) support
- Multi-key encryption (shared access)
- Forward secrecy

## Cryptographic Details

### Algorithms Used

- **Key Derivation**: HKDF-SHA256
- **Symmetric Encryption**: ChaCha20-Poly1305, AES-256-GCM
- **Compression**: LZMA (tar.xz), zlib
- **Hashing**: SHA-256

### Key Sizes

- **Master Key**: 512 bits (64 bytes)
- **Layer Keys**: 256 bits each (32 bytes)
- **Salt**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes)

### File Format

```
Header (54 bytes):
  - Magic: "DEXTR" (5 bytes)
  - Version: 1 byte
  - Key ID: 16 bytes
  - Salt: 32 bytes

Payload:
  - Nonce (12 bytes) + Ciphertext (variable) for each layer
```

## Compliance

dextr uses cryptographic primitives that are:

- NIST approved (AES-256-GCM)
- Modern and recommended (ChaCha20-Poly1305)
- Widely reviewed and adopted
- Implemented in the PyCA cryptography library

## Acknowledgments

We thank the security research community for helping keep dextr secure. Security researchers who responsibly disclose vulnerabilities will be acknowledged (with permission) in release notes.

---

**Last Updated**: 2025-11-08
**Version**: 1.2.0
