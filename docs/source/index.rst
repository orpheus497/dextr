Welcome to dextr's documentation!
=====================================

**dextr** is a secure archiving and encryption system with multi-layer AEAD encryption,
providing military-grade security for your sensitive data.

Created by **orpheus497**, dextr combines ChaCha20-Poly1305 and AES-256-GCM encryption
in a 4-layer architecture to ensure maximum security for archived files.

Features
--------

- **Multi-layer AEAD Encryption**: 4 layers using ChaCha20-Poly1305 and AES-256-GCM
- **HKDF Key Derivation**: HKDF-SHA256 with unique salts per archive
- **Password-Protected Keys**: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2024)
- **Archive Integrity Checking**: Quick and full validation modes
- **Cross-Platform**: Linux, macOS, Windows, Termux
- **ZSTD Compression**: Fast compression with excellent ratios
- **Progress Tracking**: Built-in progress bars with tqdm
- **100% FOSS**: All dependencies are Free and Open Source Software

Installation
------------

Install from PyPI:

.. code-block:: bash

   pip install dextr

Or install from source:

.. code-block:: bash

   git clone https://github.com/orpheus497/dextr.git
   cd dextr
   pip install -e .

Quick Start
-----------

Generate an encryption key:

.. code-block:: bash

   python -m dextr generate mykey.dxk

Encrypt files:

.. code-block:: bash

   python -m dextr encrypt -k mykey.dxk -i files/ -o archive.dxe

Decrypt archive:

.. code-block:: bash

   python -m dextr decrypt -k mykey.dxk -i archive.dxe -o restored/

Check integrity:

.. code-block:: bash

   python -m dextr check -k mykey.dxk -i archive.dxe

Table of Contents
-----------------

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   api
   examples
   security

API Reference
-------------

Complete API documentation for all modules:

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Examples
--------

See the ``examples/`` directory for practical usage examples:

- ``basic_encryption.py`` - Simple encryption workflow
- ``batch_encryption.py`` - Multiple files/directories
- ``automated_backup.py`` - Production backup script
- ``secure_transfer.py`` - Secure file sharing
- ``progress_tracking.py`` - Custom progress callbacks

Security
--------

dextr implements multiple layers of security:

**Encryption Layers**:

1. **Layer 1**: ChaCha20-Poly1305 (inner)
2. **Layer 2**: AES-256-GCM
3. **Layer 3**: ChaCha20-Poly1305
4. **Layer 4**: AES-256-GCM (outer)

Each layer uses unique keys derived via HKDF-SHA256 from the master key.

**Key Protection**:

- Optional password protection using PBKDF2-HMAC-SHA256
- 600,000 iterations (OWASP 2024 recommendation)
- Unique salt per key file
- AES-256-GCM for encrypted key material

**Archive Integrity**:

- HMAC-SHA256 validation at each layer
- Optional full decryption verification
- Tamper detection via authenticated encryption

License
-------

See the LICENSE file for details.

Author
------

Created by **orpheus497**

Project Repository: https://github.com/orpheus497/dextr
