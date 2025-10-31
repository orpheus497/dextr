#!/usr/bin/env python
"""
Main entry point for the dextr application.

This script allows the dextr package to be executed directly.
It simply imports and calls the main function from the CLI module.
Cross-platform compatible: Linux, macOS, Windows, Termux.
"""

import sys
from dextr.cli import main

if __name__ == '__main__':
    sys.exit(main())
