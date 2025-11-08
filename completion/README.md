# Shell Completion Scripts for dextr

This directory contains shell completion scripts for the dextr command-line interface.

## Installation

### Bash

**System-wide installation (requires root):**
```bash
sudo cp dextr.bash /etc/bash_completion.d/dextr
```

**User installation:**
```bash
mkdir -p ~/.local/share/bash-completion/completions
cp dextr.bash ~/.local/share/bash-completion/completions/dextr
```

**Temporary (current session only):**
```bash
source completion/dextr.bash
```

### Zsh

**With Oh-My-Zsh:**
```bash
mkdir -p ~/.oh-my-zsh/custom/plugins/dextr
cp dextr.zsh ~/.oh-my-zsh/custom/plugins/dextr/_dextr
```

**Manual installation:**
```bash
# Add to a directory in your $fpath
mkdir -p ~/.zsh/completion
cp dextr.zsh ~/.zsh/completion/_dextr

# Add to ~/.zshrc:
fpath=(~/.zsh/completion $fpath)
autoload -U compinit && compinit
```

### Fish

```bash
mkdir -p ~/.config/fish/completions
cp dextr.fish ~/.config/fish/completions/
```

## Usage

After installation, restart your shell or source your shell configuration file.

### Examples

```bash
# Autocomplete commands
dextr <TAB>

# Autocomplete options for a command
dextr encrypt <TAB>

# Autocomplete key files
dextr encrypt -k <TAB>

# Autocomplete help topics
dextr help <TAB>
```

## Supported Features

- Command name completion
- Option/flag completion
- File path completion with type filtering (.dxk, .dxe)
- Help topic completion
- Context-aware completions based on command

## Troubleshooting

**Bash**: If completion doesn't work, ensure bash-completion package is installed.
**Zsh**: Run `compinit` to rebuild completion cache.
**Fish**: Run `fish_update_completions` to refresh completions.

---

Created by orpheus497
