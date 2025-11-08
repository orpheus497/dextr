API Reference
=============

This page contains the complete API reference for all dextr modules.

Core Module
-----------

The core module provides the main encryption and decryption functionality.

.. automodule:: dextr.core
   :members:
   :undoc-members:
   :show-inheritance:

Key Functions
~~~~~~~~~~~~~

.. autofunction:: dextr.core.generate_key_file

.. autofunction:: dextr.core.load_key_file

.. autofunction:: dextr.core.encrypt_paths

.. autofunction:: dextr.core.decrypt_archive

.. autofunction:: dextr.core.check_archive_integrity

.. autofunction:: dextr.core.get_archive_info

Key Protection Module
---------------------

Password-based key file protection.

.. automodule:: dextr.key_protection
   :members:
   :undoc-members:
   :show-inheritance:

Key Functions
~~~~~~~~~~~~~

.. autofunction:: dextr.key_protection.encrypt_key_with_password

.. autofunction:: dextr.key_protection.decrypt_key_with_password

.. autofunction:: dextr.key_protection.is_password_protected

.. autofunction:: dextr.key_protection.prompt_password

.. autofunction:: dextr.key_protection.read_password_from_file

.. autofunction:: dextr.key_protection.get_password_strength

Constants
~~~~~~~~~

.. autodata:: dextr.key_protection.PASSWORD_ITERATIONS
   :annotation:

.. autodata:: dextr.key_protection.PASSWORD_SALT_SIZE
   :annotation:

.. autodata:: dextr.key_protection.PASSWORD_KEY_SIZE
   :annotation:

Crypto Module
-------------

Low-level cryptographic operations.

.. automodule:: dextr.crypto
   :members:
   :undoc-members:
   :show-inheritance:

Functions
~~~~~~~~~

.. autofunction:: dextr.crypto.derive_layer_keys

.. autofunction:: dextr.crypto.encrypt_data

.. autofunction:: dextr.crypto.decrypt_data

.. autofunction:: dextr.crypto.compress_data

.. autofunction:: dextr.crypto.decompress_data

Archive Module
--------------

Archive file format handling.

.. automodule:: dextr.archive
   :members:
   :undoc-members:
   :show-inheritance:

Classes
~~~~~~~

.. autoclass:: dextr.archive.ArchiveWriter
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: dextr.archive.ArchiveReader
   :members:
   :undoc-members:
   :show-inheritance:

CLI Module
----------

Command-line interface implementation.

.. automodule:: dextr.cli
   :members:
   :undoc-members:
   :show-inheritance:

Command Functions
~~~~~~~~~~~~~~~~~

.. autofunction:: dextr.cli.cmd_generate

.. autofunction:: dextr.cli.cmd_encrypt

.. autofunction:: dextr.cli.cmd_decrypt

.. autofunction:: dextr.cli.cmd_list

.. autofunction:: dextr.cli.cmd_info

.. autofunction:: dextr.cli.cmd_check

Config Module
-------------

Configuration file handling.

.. automodule:: dextr.config
   :members:
   :undoc-members:
   :show-inheritance:

Functions
~~~~~~~~~

.. autofunction:: dextr.config.load_config_file

.. autofunction:: dextr.config.get_default_config

.. autofunction:: dextr.config.merge_configs

Exceptions Module
-----------------

Custom exception classes.

.. automodule:: dextr.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

Exception Classes
~~~~~~~~~~~~~~~~~

.. autoexception:: dextr.exceptions.DextrError
   :members:
   :show-inheritance:

.. autoexception:: dextr.exceptions.KeyManagementError
   :members:
   :show-inheritance:

.. autoexception:: dextr.exceptions.EncryptionError
   :members:
   :show-inheritance:

.. autoexception:: dextr.exceptions.DecryptionError
   :members:
   :show-inheritance:

.. autoexception:: dextr.exceptions.ArchiveError
   :members:
   :show-inheritance:

.. autoexception:: dextr.exceptions.ConfigError
   :members:
   :show-inheritance:

Version Module
--------------

Version information.

.. automodule:: dextr.version
   :members:
   :undoc-members:

Constants
~~~~~~~~~

.. autodata:: dextr.version.__version__
   :annotation:

.. autodata:: dextr.version.__version_info__
   :annotation:

Utilities Module
----------------

Utility functions and helpers.

.. automodule:: dextr.utils
   :members:
   :undoc-members:
   :show-inheritance:

Type Definitions
----------------

Common type aliases and definitions used throughout the codebase.

Master Key
~~~~~~~~~~

The master key is a 512-bit (64-byte) cryptographic key used for encryption:

.. code-block:: python

   master_key: bytes  # 64 bytes (512 bits)

Key Metadata
~~~~~~~~~~~~

Key file metadata dictionary:

.. code-block:: python

   {
       "key_id": str,           # SHA-256 hash of key material
       "created": str,          # ISO format timestamp
       "username": str,         # Optional username
       "version": int,          # Key file format version
       "protected": bool        # True if password-protected
   }

Archive Metadata
~~~~~~~~~~~~~~~~

Archive file metadata dictionary:

.. code-block:: python

   {
       "created": str,                    # ISO format timestamp
       "encryption_algorithm": str,       # e.g., "ChaCha20-Poly1305+AES-256-GCM"
       "compression_algorithm": str,      # e.g., "zstd"
       "encryption_layers": int,          # Number of encryption layers
       "file_count": int,                 # Number of files in archive
       "total_size": int                  # Total uncompressed size
   }
