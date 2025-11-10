#!/bin/sh
# Universal launcher script for dextr
# Works on Linux, macOS, and Termux

# Try to find Python
if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo "Error: Python 3.8+ is required but not found in PATH" >&2
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Run dextr
exec "$PYTHON" "$SCRIPT_DIR/dextr.py" "$@"
