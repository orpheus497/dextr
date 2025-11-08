# Dextr Documentation

This directory contains the Sphinx documentation for dextr.

## Building Documentation

### Prerequisites

Install documentation dependencies:

```bash
pip install -r requirements.txt
```

Or install with dextr development dependencies:

```bash
pip install -r ../requirements-dev.txt
```

### Build HTML Documentation

**Linux/macOS:**

```bash
cd docs
make html
```

**Windows:**

```cmd
cd docs
make.bat html
```

The generated HTML will be in `build/html/`. Open `build/html/index.html` in your browser.

### Other Build Formats

```bash
# PDF (requires LaTeX)
make latexpdf

# Plain text
make text

# Man pages
make man

# ePub
make epub

# Clean build directory
make clean
```

## Documentation Structure

```
docs/
├── source/
│   ├── conf.py          # Sphinx configuration
│   ├── index.rst        # Main documentation page
│   ├── api.rst          # API reference
│   ├── examples.rst     # Usage examples
│   └── security.rst     # Security documentation
├── build/               # Generated documentation (git-ignored)
├── requirements.txt     # Documentation dependencies
├── Makefile            # Build script (Unix)
└── make.bat            # Build script (Windows)
```

## Contributing

When adding new modules or features:

1. Add docstrings to all functions/classes
2. Update `api.rst` with new module references
3. Add examples to `examples.rst` if applicable
4. Rebuild and verify documentation locally

## Viewing Online

Documentation will be hosted at:
- GitHub Pages (planned)
- ReadTheDocs (planned)
