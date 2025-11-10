#!/bin/bash
# Automated installation script for dextr
# Works on Linux, macOS, and Termux

set -e  # Exit on error

echo "╔══════════════════════════════════════════════════╗"
echo "║        dextr Installation Script v1.3.0          ║"
echo "║    Secure Archiving & Encryption System          ║"
echo "║          Created by orpheus497                   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -d "/data/data/com.termux" ]; then
            OS="termux"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    echo "$OS"
}

# Check Python installation
check_python() {
    print_info "Checking Python installation..."

    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        print_success "Found Python $PYTHON_VERSION"

        # Check if version is 3.8+
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
            return 0
        else
            print_error "Python 3.8+ is required (found $PYTHON_VERSION)"
            return 1
        fi
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)

        if [ "$MAJOR" -eq 3 ]; then
            PYTHON_CMD="python"
            print_success "Found Python $PYTHON_VERSION"

            MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
            if [ "$MINOR" -ge 8 ]; then
                return 0
            else
                print_error "Python 3.8+ is required (found $PYTHON_VERSION)"
                return 1
            fi
        else
            print_error "Python 3.8+ is required (found Python $MAJOR)"
            return 1
        fi
    else
        print_error "Python not found"
        return 1
    fi
}

# Check pip installation
check_pip() {
    print_info "Checking pip installation..."

    if $PYTHON_CMD -m pip --version &> /dev/null; then
        print_success "pip is installed"
        return 0
    else
        print_error "pip is not installed"
        return 1
    fi
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."

    if $PYTHON_CMD -m pip install --user -r requirements.txt; then
        print_success "Dependencies installed successfully"
        return 0
    else
        print_error "Failed to install dependencies"
        return 1
    fi
}

# Install dextr
install_dextr() {
    echo ""
    echo "Choose installation method:"
    echo "  1) System-wide installation (requires sudo/admin on some systems)"
    echo "  2) User installation (recommended, no special privileges needed)"
    echo "  3) Development mode (for developers)"
    echo "  4) Skip installation (just install dependencies)"
    echo ""
    read -p "Enter choice [1-4]: " choice

    case $choice in
        1)
            print_info "Installing dextr system-wide..."
            if $PYTHON_CMD -m pip install .; then
                print_success "dextr installed system-wide"
                INSTALL_METHOD="system"
                return 0
            else
                print_error "System-wide installation failed. Try user installation instead."
                return 1
            fi
            ;;
        2)
            print_info "Installing dextr for current user..."
            if $PYTHON_CMD -m pip install --user .; then
                print_success "dextr installed for user"
                INSTALL_METHOD="user"
                return 0
            else
                print_error "User installation failed"
                return 1
            fi
            ;;
        3)
            print_info "Installing dextr in development mode..."
            if $PYTHON_CMD -m pip install --user -e .; then
                print_success "dextr installed in development mode"
                INSTALL_METHOD="dev"
                return 0
            else
                print_error "Development installation failed"
                return 1
            fi
            ;;
        4)
            print_info "Skipping dextr installation"
            INSTALL_METHOD="none"
            return 0
            ;;
        *)
            print_error "Invalid choice"
            return 1
            ;;
    esac
}

# Make scripts executable
make_executable() {
    print_info "Making scripts executable..."
    chmod +x run.sh dextr.py
    print_success "Scripts are now executable"
}

# Test installation
test_installation() {
    print_info "Testing installation..."

    if [ "$INSTALL_METHOD" = "none" ]; then
        if ./run.sh --version &> /dev/null; then
            print_success "Direct execution works: ./run.sh --version"
            return 0
        else
            print_error "Installation test failed"
            return 1
        fi
    else
        if command -v dextr &> /dev/null; then
            print_success "Command 'dextr' is available"
            if dextr --version &> /dev/null; then
                print_success "dextr is working correctly"
                return 0
            else
                print_error "dextr command failed"
                return 1
            fi
        else
            print_error "dextr command not found in PATH"
            echo ""
            echo "You may need to add the installation directory to your PATH:"

            OS=$(detect_os)
            if [ "$OS" = "linux" ] || [ "$OS" = "termux" ]; then
                echo "  Linux/Termux: export PATH=\"\$HOME/.local/bin:\$PATH\""
                echo "  Add to ~/.bashrc or ~/.zshrc to make permanent"
            elif [ "$OS" = "macos" ]; then
                echo "  macOS: export PATH=\"\$HOME/Library/Python/*/bin:\$PATH\""
                echo "  Add to ~/.bash_profile or ~/.zshrc to make permanent"
            fi

            echo ""
            echo "Alternatively, you can use: ./run.sh [command]"
            return 1
        fi
    fi
}

# Display post-installation info
show_usage() {
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║           Installation Complete!                 ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""

    if [ "$INSTALL_METHOD" = "none" ]; then
        echo "Usage: ./run.sh [command]"
    else
        echo "Usage: dextr [command]"
        echo "   or: ./run.sh [command]"
    fi

    echo ""
    echo "Quick Start:"
    echo "  1. Generate a key:    dextr generate"
    echo "  2. Encrypt files:     dextr encrypt -k key.dxk -i file.txt -o backup.dxe"
    echo "  3. Decrypt archive:   dextr decrypt -k key.dxk -i backup.dxe -o restored/"
    echo "  4. View key info:     dextr info -k key.dxk"
    echo ""
    echo "Documentation:"
    echo "  - Full guide:         cat README.md"
    echo "  - Quick reference:    cat USAGE.md"
    echo "  - Help:               dextr --help"
    echo ""
    echo "For detailed help, run: dextr help"
    echo ""
}

# Main installation flow
main() {
    OS=$(detect_os)
    print_info "Detected OS: $OS"
    echo ""

    # Check Python
    if ! check_python; then
        echo ""
        echo "Please install Python 3.8 or higher:"
        if [ "$OS" = "linux" ]; then
            echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
            echo "  Fedora:        sudo dnf install python3 python3-pip"
            echo "  Arch:          sudo pacman -S python python-pip"
        elif [ "$OS" = "macos" ]; then
            echo "  brew install python3"
            echo "  or download from: https://www.python.org/downloads/"
        elif [ "$OS" = "termux" ]; then
            echo "  pkg install python"
        fi
        exit 1
    fi

    echo ""

    # Check pip
    if ! check_pip; then
        echo ""
        echo "Please install pip:"
        if [ "$OS" = "linux" ]; then
            echo "  Ubuntu/Debian: sudo apt install python3-pip"
            echo "  Fedora:        sudo dnf install python3-pip"
        elif [ "$OS" = "macos" ]; then
            echo "  $PYTHON_CMD -m ensurepip --upgrade"
        elif [ "$OS" = "termux" ]; then
            echo "  pkg install python-pip"
        fi
        exit 1
    fi

    echo ""

    # Install dependencies
    if ! install_dependencies; then
        echo ""
        print_error "Failed to install dependencies"
        exit 1
    fi

    echo ""

    # Make scripts executable
    make_executable

    echo ""

    # Install dextr
    if ! install_dextr; then
        echo ""
        print_error "Installation incomplete, but you can still use: ./run.sh [command]"
        exit 1
    fi

    echo ""

    # Test installation
    test_installation

    # Show usage
    show_usage
}

# Run main function
main
