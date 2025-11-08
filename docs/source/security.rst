Security
========

This document describes the security architecture and best practices for dextr.

Encryption Architecture
-----------------------

Multi-Layer AEAD
~~~~~~~~~~~~~~~~

dextr uses a 4-layer AEAD (Authenticated Encryption with Associated Data) architecture:

**Layer 1 (Innermost)**
   - Algorithm: ChaCha20-Poly1305
   - Purpose: Primary data encryption
   - Key: Derived from master key via HKDF

**Layer 2**
   - Algorithm: AES-256-GCM
   - Purpose: Secondary encryption
   - Key: Unique derived key

**Layer 3**
   - Algorithm: ChaCha20-Poly1305
   - Purpose: Tertiary encryption
   - Key: Unique derived key

**Layer 4 (Outermost)**
   - Algorithm: AES-256-GCM
   - Purpose: Final encryption layer
   - Key: Unique derived key

Each layer provides:

- **Confidentiality**: Data encryption
- **Integrity**: Authentication tags (HMAC-SHA256)
- **Authenticity**: Verification of data origin

Key Derivation
~~~~~~~~~~~~~~

dextr uses HKDF-SHA256 (HMAC-based Key Derivation Function) to derive layer-specific
keys from the master key:

.. code-block:: python

   layer_key = HKDF(
       algorithm=SHA256,
       length=32,  # 256 bits
       salt=unique_salt,
       info=layer_info
   ).derive(master_key)

Each archive has:

- Unique salt (32 bytes, cryptographically random)
- Unique layer keys derived for each encryption layer
- Master key is never used directly for encryption

Master Key
~~~~~~~~~~

The master key is:

- **Length**: 512 bits (64 bytes)
- **Source**: Cryptographically secure random generator (``secrets.token_bytes(64)``)
- **Usage**: Key derivation only (never direct encryption)
- **Storage**: Key file with optional password protection

Password Protection
-------------------

PBKDF2 Key Derivation
~~~~~~~~~~~~~~~~~~~~~

Password-protected keys use PBKDF2-HMAC-SHA256:

- **Iterations**: 600,000 (OWASP 2024 recommendation)
- **Salt**: 32 bytes, unique per key file
- **Derived Key**: 256 bits (32 bytes)
- **Algorithm**: PBKDF2-HMAC-SHA256

Implementation:

.. code-block:: python

   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   from cryptography.hazmat.primitives import hashes

   kdf = PBKDF2HMAC(
       algorithm=hashes.SHA256(),
       length=32,
       salt=salt,
       iterations=600000
   )
   derived_key = kdf.derive(password.encode('utf-8'))

Key Encryption
~~~~~~~~~~~~~~

The derived key encrypts the master key using AES-256-GCM:

- **Algorithm**: AES-256-GCM
- **Key**: Derived from password via PBKDF2
- **Nonce**: 96 bits, unique per encryption
- **Authentication**: GCM authentication tag

Password Strength
~~~~~~~~~~~~~~~~~

dextr evaluates password strength:

.. code-block:: python

   from dextr.key_protection import get_password_strength

   strength = get_password_strength(password)
   # Returns: {
   #   'strength': 'weak'|'medium'|'strong',
   #   'score': 0-100,
   #   'length': int,
   #   'has_upper': bool,
   #   'has_lower': bool,
   #   'has_digits': bool,
   #   'has_special': bool
   # }

**Strength Criteria**:

- **Weak** (< 40 points): Short, single-case, no variety
- **Medium** (40-69 points): Moderate length, some variety
- **Strong** (70+ points): Long, mixed case, digits, special characters

**Recommendations**:

- Minimum 16 characters
- Mix of uppercase, lowercase, digits, special characters
- Avoid dictionary words and common patterns
- Use a password manager for generation

Compression Security
--------------------

ZSTD Compression
~~~~~~~~~~~~~~~~

dextr uses Zstandard (ZSTD) compression:

- Applied **before** encryption
- Compression level: 3 (default)
- No security implications (compression is a preprocessing step)

Security Note
~~~~~~~~~~~~~

Compression before encryption is safe in this context because:

1. dextr is designed for file archiving, not streaming data
2. AEAD provides integrity protection
3. No sensitive length information leaks (all layers encrypted)

For highly sensitive applications where side-channel attacks are a concern,
compression can be disabled via configuration.

Archive Integrity
-----------------

Validation Modes
~~~~~~~~~~~~~~~~

**Quick Mode**
   - Validates first (outer) encryption layer
   - Fast verification (no full decryption)
   - Detects: Corruption, tampering at outer layer

**Full Mode**
   - Decrypts all 4 layers
   - Validates compression
   - Detects: All forms of corruption, tampering at any layer

Implementation
~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import check_archive_integrity

   # Quick check
   result = check_archive_integrity("archive.dxe", master_key, quick=True)

   # Full validation
   result = check_archive_integrity("archive.dxe", master_key, quick=False)

Each layer validates:

1. **Nonce uniqueness**: Each layer has unique nonce
2. **Authentication tag**: GCM/Poly1305 tags verified
3. **Decryption success**: Data decrypts correctly
4. **Compression integrity**: Decompressed data is valid

Threat Model
------------

Protected Against
~~~~~~~~~~~~~~~~~

**Passive Attacks**
   ✓ Eavesdropping on archived data
   ✓ Data recovery from storage media
   ✓ Network interception (if transmitting archives)

**Active Attacks**
   ✓ Archive modification/tampering (detected via AEAD tags)
   ✓ Layer removal (detected in integrity check)
   ✓ Bit-flipping attacks (authenticated encryption prevents)

**Cryptographic Attacks**
   ✓ Known-plaintext attacks (modern AEAD algorithms)
   ✓ Chosen-plaintext attacks (AEAD provides security)
   ✓ Brute-force attacks (512-bit master keys, 600k PBKDF2 iterations)

**Side-Channel Attacks**
   ✓ Timing attacks (constant-time crypto operations)
   ✓ Storage analysis (compression before encryption)

Not Protected Against
~~~~~~~~~~~~~~~~~~~~~~

**Out of Scope**
   ✗ Key compromise (if attacker obtains key file + password)
   ✗ Malware on encryption/decryption system
   ✗ Rubber-hose cryptanalysis (physical coercion)
   ✗ Quantum computing attacks (future threat, not current)

**Physical Security**
   ✗ Physical access to unlocked systems
   ✗ Cold boot attacks on running systems
   ✗ Hardware keyloggers

**Operational Security**
   ✗ Weak passwords (user responsibility)
   ✗ Key file exposure (storage security responsibility)
   ✗ Social engineering

Best Practices
--------------

Key Management
~~~~~~~~~~~~~~

1. **Generate Strong Keys**

   .. code-block:: bash

      python -m dextr generate mykey.dxk --password

2. **Secure Key Storage**

   - Set proper file permissions: ``chmod 600 mykey.dxk``
   - Store in encrypted filesystems
   - Keep backups in separate secure locations
   - Never commit keys to version control

3. **Password Selection**

   - Use 16+ character passwords
   - Generate with password managers
   - Avoid reusing passwords
   - Consider passphrase format (e.g., 6+ random words)

Archive Management
~~~~~~~~~~~~~~~~~~

1. **Verify After Creation**

   .. code-block:: bash

      python -m dextr check -k mykey.dxk -i archive.dxe --full

2. **Regular Integrity Checks**

   Periodically verify archived data hasn't been corrupted

3. **Backup Strategy**

   - Multiple copies (3-2-1 rule)
   - Different geographic locations
   - Regular testing of restore procedures

Operational Security
~~~~~~~~~~~~~~~~~~~~

1. **Secure Deletion**

   After encrypting sensitive files:

   .. code-block:: bash

      shred -vfz -n 3 sensitive_file.txt

2. **Environment Security**

   - Use trusted, malware-free systems
   - Keep systems updated
   - Use full-disk encryption on storage devices

3. **Access Control**

   - Limit who has access to keys
   - Use password protection for keys
   - Log and monitor key usage in sensitive environments

4. **Network Transfer**

   - Use secure channels (SSH, HTTPS, VPN)
   - Verify archive integrity after transfer
   - Consider separate channels for key and archive

Compliance
----------

Standards Alignment
~~~~~~~~~~~~~~~~~~~

dextr's cryptography aligns with:

- **NIST**: Uses NIST-approved algorithms (AES, SHA-256)
- **OWASP**: 600,000 PBKDF2 iterations (2024 recommendation)
- **IETF**: Standard algorithms (RFC 7539 ChaCha20-Poly1305, RFC 5869 HKDF)

Algorithm Selection
~~~~~~~~~~~~~~~~~~~

All algorithms are:

- Publicly reviewed and standardized
- Recommended by cryptographic community
- Implemented in audited libraries (cryptography.io)
- Actively maintained and updated

Dependencies Security
~~~~~~~~~~~~~~~~~~~~~

All dependencies are FOSS:

- ``cryptography``: Well-audited Python cryptography library
- ``zstandard``: Facebook's ZSTD compression
- ``tqdm``: Progress bars

Regular security updates via:

- Dependabot automated updates
- GitHub security advisories
- CI/CD security scanning (Bandit, Safety)

Audit History
-------------

**Internal Audits**:

- Regular code reviews
- Automated security scanning (Bandit)
- Dependency vulnerability scanning (Safety)

**External Audits**:

- Not yet performed (contributions welcome)

**Bug Bounty**:

- Not currently active

To report security issues: GitHub Issues or contact maintainer directly

Future Enhancements
-------------------

Potential future improvements:

1. **Post-Quantum Cryptography**: Evaluate NIST PQC algorithms when standardized
2. **Hardware Security Module (HSM)**: Support for HSM key storage
3. **Multi-Factor Key Protection**: Combine password + hardware token
4. **Key Rotation**: Tools for re-encrypting archives with new keys
5. **Formal Verification**: Mathematical proof of security properties

Contributions welcome on all fronts!
