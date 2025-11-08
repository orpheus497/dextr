"""
dextr/config.py

Configuration file management for the dextr application.
Supports loading configuration from TOML files with cascading defaults.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

try:
    # Python 3.11+
    import tomllib
except ImportError:
    try:
        # Python 3.7-3.10, use tomli
        import tomli as tomllib
    except ImportError:
        # If tomli not installed, fall back to simple parser
        tomllib = None


# Default configuration values
DEFAULT_CONFIG = {
    "max_archive_size_mb": 10240,  # 10 GB default
    "compression_level": 9,  # Maximum compression
    "chunk_size_mb": 64,  # 64 MB chunks for streaming
    "default_key_path": "",  # No default key path
    "log_level": "INFO",
    "log_file": "",  # No log file by default
}


def _simple_toml_parse(content: str) -> Dict[str, Any]:
    """
    Simple TOML parser for basic key=value pairs.
    Supports sections and basic data types (strings, integers, booleans).

    This is a fallback for Python < 3.11 without external dependencies.

    Args:
        content: TOML file content

    Returns:
        Parsed configuration dictionary
    """
    config: Dict[str, Any] = {}
    current_section = None

    for line in content.split("\n"):
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Section headers
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            if current_section not in config:
                config[current_section] = {}
            continue

        # Key-value pairs
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Remove quotes from strings
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]
            # Parse integers
            elif value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
                value = int(value)
            # Parse booleans
            elif value.lower() in ("true", "false"):
                value = value.lower() == "true"

            # Add to appropriate section
            if current_section:
                config[current_section][key] = value
            else:
                config[key] = value

    return config


def load_config_file(path: Path) -> Dict[str, Any]:
    """
    Load configuration from a TOML file.

    Args:
        path: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config file is malformed
    """
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    try:
        # Try using tomllib (Python 3.11+) or tomli (Python 3.7-3.10)
        if tomllib is not None:
            # tomllib/tomli requires binary mode
            with open(path, "rb") as f:
                config = tomllib.load(f)
        else:
            # Fallback to simple parser if tomli not installed
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            config = _simple_toml_parse(content)

        return config

    except Exception as e:
        raise ValueError(f"Failed to parse configuration file: {e}") from e


def get_config_path() -> Optional[Path]:
    """
    Find the configuration file path.

    Searches in the following order:
    1. ./.dextr.conf (current directory)
    2. ~/.dextr.conf (user home directory)
    3. ~/.config/dextr/config.toml (XDG config directory on Unix)

    Returns:
        Path to config file if found, None otherwise
    """
    # Current directory
    local_config = Path(".dextr.conf")
    if local_config.exists():
        return local_config

    # User home directory
    home_config = Path.home() / ".dextr.conf"
    if home_config.exists():
        return home_config

    # XDG config directory (Unix-like systems)
    if os.name != "nt":
        xdg_config = Path.home() / ".config" / "dextr" / "config.toml"
        if xdg_config.exists():
            return xdg_config

    return None


def load_config() -> Dict[str, Any]:
    """
    Load configuration with defaults.

    Searches for configuration files and merges with defaults.

    Returns:
        Complete configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()

    config_path = get_config_path()
    if config_path:
        try:
            file_config = load_config_file(config_path)

            # Merge dextr section if it exists
            if "dextr" in file_config:
                config.update(file_config["dextr"])

            # Merge logging section if it exists
            if "logging" in file_config:
                if "log_level" in file_config["logging"]:
                    config["log_level"] = file_config["logging"]["log_level"]
                if "log_file" in file_config["logging"]:
                    config["log_file"] = file_config["logging"]["log_file"]

        except (FileNotFoundError, ValueError):
            # If config file is malformed or missing, use defaults
            pass

    return config


def merge_config(config: Dict[str, Any], cli_args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge configuration with command-line arguments.

    CLI arguments take precedence over config file values.

    Args:
        config: Configuration dictionary from file
        cli_args: Dictionary of CLI arguments

    Returns:
        Merged configuration
    """
    merged = config.copy()

    # Override with CLI arguments if provided
    for key, value in cli_args.items():
        if value is not None:
            merged[key] = value

    return merged


def create_default_config(path: Path) -> None:
    """
    Create a default configuration file.

    Args:
        path: Path where config file should be created
    """
    config_content = """# dextr Configuration File
# This file uses TOML format: https://toml.io/

[dextr]
# Maximum archive size in megabytes (default: 10240 = 10 GB)
max_archive_size_mb = 10240

# Compression level: 1 (fast) to 9 (best compression)
compression_level = 9

# Chunk size for streaming operations in megabytes (default: 64 MB)
chunk_size_mb = 64

# Default key file path (leave empty for no default)
default_key_path = ""

[logging]
# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = "INFO"

# Log file path (leave empty to disable file logging)
log_file = ""
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(config_content)


def get_max_archive_size(config: Dict[str, Any]) -> Optional[int]:
    """
    Get maximum archive size in bytes from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        Maximum size in bytes, or None for no limit
    """
    max_size_mb = config.get("max_archive_size_mb")
    if max_size_mb is None or max_size_mb <= 0:
        return None
    return max_size_mb * 1024 * 1024


def get_chunk_size(config: Dict[str, Any]) -> int:
    """
    Get chunk size for streaming operations in bytes.

    Args:
        config: Configuration dictionary

    Returns:
        Chunk size in bytes
    """
    chunk_size_mb = config.get("chunk_size_mb", 64)
    return max(1, chunk_size_mb) * 1024 * 1024


def get_compression_level(config: Dict[str, Any]) -> int:
    """
    Get compression level from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        Compression level (1-9)
    """
    level = config.get("compression_level", 9)
    return max(1, min(9, level))
