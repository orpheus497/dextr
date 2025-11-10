#!/bin/bash
# Test runner script for debugging

# Try to find Python (prefer python3)
if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo "Error: Python 3.8+ is required but not found in PATH" >&2
    exit 1
fi

echo "=== Running dextr tests ==="
echo "Python: $($PYTHON --version)"
echo "Pytest: $($PYTHON -m pytest --version 2>&1 || echo 'NOT INSTALLED')"
echo "Working directory: $(pwd)"
echo

# Run tests
$PYTHON -m pytest tests/ -v --tb=short

# Check exit code
if [ $? -eq 0 ]; then
    echo
    echo "✓ ALL TESTS PASSED"
else
    echo
    echo "✗ TESTS FAILED"
    exit 1
fi
