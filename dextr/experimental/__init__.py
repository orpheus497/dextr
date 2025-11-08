"""
dextr/experimental/__init__.py

EXPERIMENTAL MODULES - NOT PRODUCTION-READY

This package contains experimental modules that are under active development.
These modules are NOT yet production-ready and should NOT be used in production
environments.

Current experimental modules:
- streaming: Memory-efficient streaming encryption/decryption (incomplete)

WARNING: APIs in this package may change without notice and may contain bugs.
Use at your own risk for testing and development purposes only.
"""

__all__ = ["streaming"]

# Do not import by default - require explicit import
# Users must explicitly: from dextr.experimental import streaming
