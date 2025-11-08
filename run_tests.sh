#!/bin/bash
# Test runner script for debugging

echo "=== Running dextr tests ==="
echo "Python: $(python --version)"
echo "Pytest: $(python -m pytest --version)"
echo "Working directory: $(pwd)"
echo

# Run tests
python -m pytest tests/ -v --tb=short

# Check exit code
if [ $? -eq 0 ]; then
    echo
    echo "✓ ALL TESTS PASSED"
else
    echo
    echo "✗ TESTS FAILED"
    exit 1
fi
