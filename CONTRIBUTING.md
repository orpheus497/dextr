# Contributing to dextr

Thank you for your interest in contributing to dextr! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear Title**: Descriptive summary of the issue
- **Steps to Reproduce**: Detailed steps to reproduce the behavior
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**: OS, Python version, dextr version
- **Logs**: Relevant log output or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use Case**: Why this enhancement would be useful
- **Proposed Solution**: How you envision it working
- **Alternatives**: Other approaches you've considered
- **Examples**: Similar features in other tools

### Security Vulnerabilities

**DO NOT** report security vulnerabilities as GitHub issues. Please follow the process in [SECURITY.md](SECURITY.md).

## Development Setup

### Prerequisites

- Python 3.7 or higher
- pip
- git

### Setting Up Development Environment

1. **Fork and Clone**

   ```bash
   git fork https://github.com/orpheus497/dextr
   cd dextr
   ```

2. **Create Virtual Environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**

   ```bash
   pip install -e .
   pip install -r requirements-dev.txt
   ```

4. **Verify Installation**

   ```bash
   dextr --version
   pytest
   ```

### Project Structure

```
dextr/
├── dextr/              # Main package
│   ├── __init__.py     # Package initialization
│   ├── core.py         # Cryptographic core
│   ├── cli.py          # Command-line interface
│   ├── validation.py   # Input validation
│   ├── config.py       # Configuration management
│   ├── logging_config.py # Logging setup
│   └── streaming.py    # Streaming operations
├── tests/              # Test suite
├── docs/               # Documentation
├── .dev-docs/          # AI/development documentation (not committed)
└── README.md           # Project documentation
```

## Coding Standards

### Code Style

- Follow [PEP 8](https://pep8.org/)
- Use [Black](https://black.readthedocs.io/) for formatting
- Maximum line length: 100 characters
- Use descriptive variable names

### Type Hints

- Add type hints to all function signatures
- Use `typing` module for complex types
- Run `mypy` for type checking

### Documentation

- Write docstrings for all public functions
- Use Google-style docstrings
- Include type information in docstrings
- Document exceptions that can be raised

### Example

```python
def encrypt_file(
    input_path: str,
    output_path: str,
    key: bytes,
    compression_level: int = 9
) -> None:
    """
    Encrypt a single file.

    Args:
        input_path: Path to the file to encrypt
        output_path: Path for the encrypted output
        key: Encryption key (must be 64 bytes)
        compression_level: zlib compression level (1-9, default 9)

    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If key is wrong size
        EncryptionError: If encryption fails
    """
    pass
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=dextr --cov-report=html

# Run specific test file
pytest tests/test_core.py

# Run specific test
pytest tests/test_core.py::test_generate_key
```

### Writing Tests

- Write tests for all new features
- Maintain or improve code coverage
- Use descriptive test names
- Include edge cases and error conditions
- Use pytest fixtures for common setup

### Test Structure

```python
def test_encrypt_decrypt_cycle():
    """Test that encryption followed by decryption recovers original data."""
    # Arrange
    original_data = b"test data"
    key = os.urandom(64)

    # Act
    encrypted = encrypt(original_data, key)
    decrypted = decrypt(encrypted, key)

    # Assert
    assert decrypted == original_data
```

## Code Quality Tools

### Running Checks

```bash
# Format code
black dextr/ tests/

# Type checking
mypy dextr/

# Linting
flake8 dextr/ tests/
```

### Pre-Commit Checks

Before committing, ensure:

1. All tests pass
2. Code is formatted with Black
3. Type checking passes
4. Linting passes
5. Documentation is updated

## Pull Request Process

### Before Submitting

1. Create a feature branch from `main`
2. Make your changes
3. Add/update tests
4. Update documentation
5. Run all quality checks
6. Test on multiple platforms if possible

### Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

Example:
```
feat(cli): add progress bars for encryption

Add tqdm-based progress bars that show real-time progress
during encryption and decryption operations.

Closes #123
```

### Pull Request Guidelines

1. **Title**: Clear, descriptive title
2. **Description**: Explain what and why
3. **Testing**: Describe how you tested
4. **Breaking Changes**: Clearly note any breaking changes
5. **Screenshots**: Include if UI changes
6. **Linked Issues**: Reference related issues

### Review Process

1. Maintainer will review within 7 days
2. Address review feedback
3. Squash commits if requested
4. Ensure CI passes
5. Maintainer will merge when ready

## Development Workflow

### Feature Development

```bash
# Create feature branch
git checkout -b feat/my-feature

# Make changes
# ... edit files ...

# Run tests
pytest

# Format and lint
black dextr/ tests/
flake8 dextr/ tests/

# Commit
git add .
git commit -m "feat: add my feature"

# Push
git push origin feat/my-feature

# Create pull request on GitHub
```

### Bug Fixes

```bash
# Create bugfix branch
git checkout -b fix/issue-123

# Make changes and add test
# ... edit files ...

# Verify fix
pytest tests/test_relevant.py

# Commit
git commit -m "fix: resolve issue #123"

# Push and create PR
git push origin fix/issue-123
```

## Documentation

### Updating Documentation

- Update README.md for feature changes
- Update CHANGELOG.md (in Unreleased section)
- Add docstrings for new functions
- Update examples if needed
- Consider adding to USAGE.md

### Building Documentation

```bash
# Install sphinx
pip install sphinx sphinx-rtd-theme

# Build docs
cd docs/
make html

# View docs
open _build/html/index.html
```

## Release Process

(For maintainers)

1. Update version in `__init__.py` and `setup.py`
2. Update CHANGELOG.md
3. Create release commit
4. Tag release: `git tag -a v1.2.0 -m "Release v1.2.0"`
5. Push: `git push --tags`
6. Create GitHub release
7. Build and upload to PyPI

## Questions?

If you have questions about contributing:

1. Check existing documentation
2. Search closed issues and PRs
3. Open a discussion on GitHub
4. Contact maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to dextr!**

Created by orpheus497
