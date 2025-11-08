Examples
========

This page provides detailed examples of using dextr for various use cases.

Basic Usage
-----------

Generate a Key
~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import generate_key_file

   # Generate a standard key
   metadata = generate_key_file("mykey.dxk")
   print(f"Key ID: {metadata['key_id']}")

   # Generate a password-protected key
   metadata = generate_key_file("protected.dxk", password="MySecurePassword123!")

Encrypt Files
~~~~~~~~~~~~~

.. code-block:: python

   from dextr import load_key_file, encrypt_paths

   # Load the key
   master_key, metadata = load_key_file("mykey.dxk")

   # Encrypt files and directories
   paths = ["document.pdf", "photos/", "config.ini"]
   encrypt_paths(paths, "archive.dxe", master_key)

Decrypt Archive
~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import load_key_file, decrypt_archive

   # Load the key
   master_key, metadata = load_key_file("mykey.dxk")

   # Decrypt archive
   decrypt_archive("archive.dxe", "restored/", master_key)

Password-Protected Keys
-----------------------

Creating Protected Keys
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import generate_key_file
   from dextr.key_protection import prompt_password

   # Interactive password entry
   password = prompt_password("Enter password: ", confirm=True)
   generate_key_file("protected.dxk", password=password)

.. code-block:: python

   from dextr import generate_key_file
   from dextr.key_protection import read_password_from_file

   # Read password from file
   password = read_password_from_file("password.txt")
   generate_key_file("protected.dxk", password=password)

Using Protected Keys
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import load_key_file, encrypt_paths
   from dextr.key_protection import prompt_password

   # Load password-protected key
   password = prompt_password("Enter key password: ")
   master_key, metadata = load_key_file("protected.dxk", password=password)

   # Use normally
   encrypt_paths(["files/"], "archive.dxe", master_key)

Password Strength Check
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr.key_protection import get_password_strength

   password = "MyPassword123!"
   strength = get_password_strength(password)

   print(f"Strength: {strength['strength']}")  # weak/medium/strong
   print(f"Score: {strength['score']}/100")
   print(f"Length: {strength['length']}")
   print(f"Has uppercase: {strength['has_upper']}")
   print(f"Has digits: {strength['has_digits']}")
   print(f"Has special: {strength['has_special']}")

Archive Integrity
-----------------

Quick Check
~~~~~~~~~~~

.. code-block:: python

   from dextr import load_key_file, check_archive_integrity

   master_key, _ = load_key_file("mykey.dxk")

   # Quick check (first layer only)
   result = check_archive_integrity("archive.dxe", master_key, quick=True)

   if result['valid']:
       print(f"✓ Archive is valid")
       print(f"Layers validated: {result['layers_validated']}")
   else:
       print(f"✗ Archive is invalid or corrupted")

Full Validation
~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import load_key_file, check_archive_integrity

   master_key, _ = load_key_file("mykey.dxk")

   # Full validation (all layers + decompression)
   result = check_archive_integrity("archive.dxe", master_key, quick=False)

   print(f"Valid: {result['valid']}")
   print(f"Layers: {result['layers_validated']}")
   print(f"Compression OK: {result.get('compression_valid', 'N/A')}")

Archive Information
-------------------

Get Metadata (No Key Required)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import get_archive_info

   info = get_archive_info("archive.dxe")

   print(f"Created: {info['created']}")
   print(f"Encryption: {info['encryption_algorithm']}")
   print(f"Compression: {info['compression_algorithm']}")
   print(f"Layers: {info['encryption_layers']}")

Batch Operations
----------------

Encrypt Multiple Locations
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import load_key_file, encrypt_paths

   master_key, _ = load_key_file("mykey.dxk")

   # Multiple unrelated locations in one archive
   locations = [
       "/home/user/documents",
       "/home/user/photos/vacation",
       "/etc/important-config.ini",
       "/var/backups/database.sql"
   ]

   encrypt_paths(locations, "backup.dxe", master_key)

Automated Backups
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from datetime import datetime
   from pathlib import Path
   from dextr import generate_key_file, load_key_file, encrypt_paths

   # Setup backup directory
   backup_dir = Path("backups")
   backup_dir.mkdir(exist_ok=True)

   # Generate timestamped backup
   timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
   archive_name = f"backup_{timestamp}.dxe"
   key_name = f"backup_{timestamp}.dxk"

   # Generate key
   generate_key_file(str(backup_dir / key_name))
   master_key, _ = load_key_file(str(backup_dir / key_name))

   # Encrypt
   paths_to_backup = ["/home/user/important"]
   encrypt_paths(paths_to_backup, str(backup_dir / archive_name), master_key)

   print(f"Backup created: {archive_name}")

Configuration
-------------

Load Config File
~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr.config import load_config_file

   # Load TOML config
   config = load_config_file("dextr.toml")

   print(f"Compression level: {config.get('compression_level')}")
   print(f"Encryption layers: {config.get('encryption_layers')}")

Default Configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr.config import get_default_config

   config = get_default_config()
   print(config)

Error Handling
--------------

Catching Exceptions
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from dextr import load_key_file
   from dextr.exceptions import KeyManagementError, DecryptionError

   try:
       master_key, _ = load_key_file("mykey.dxk", password="wrong")
   except KeyManagementError as e:
       print(f"Key error: {e}")

   try:
       decrypt_archive("corrupted.dxe", "output/", master_key)
   except DecryptionError as e:
       print(f"Decryption error: {e}")

Command-Line Interface
----------------------

All Python API functions have CLI equivalents:

Generate Key
~~~~~~~~~~~~

.. code-block:: bash

   # Standard key
   python -m dextr generate mykey.dxk

   # Password-protected
   python -m dextr generate mykey.dxk --password

   # From password file
   python -m dextr generate mykey.dxk --password-file pw.txt

Encrypt
~~~~~~~

.. code-block:: bash

   # Single file
   python -m dextr encrypt -k mykey.dxk -i file.txt -o file.dxe

   # Multiple paths
   python -m dextr encrypt -k mykey.dxk -i file1.txt dir/ file2.pdf -o archive.dxe

   # With password-protected key
   python -m dextr encrypt -k mykey.dxk --password -i files/ -o archive.dxe

Decrypt
~~~~~~~

.. code-block:: bash

   python -m dextr decrypt -k mykey.dxk -i archive.dxe -o restored/

Check Integrity
~~~~~~~~~~~~~~~

.. code-block:: bash

   # Quick check
   python -m dextr check -k mykey.dxk -i archive.dxe

   # Full validation
   python -m dextr check -k mykey.dxk -i archive.dxe --full

Info and List
~~~~~~~~~~~~~

.. code-block:: bash

   # Archive info (no key needed)
   python -m dextr info -i archive.dxe

   # List contents (key required)
   python -m dextr list -k mykey.dxk -i archive.dxe
