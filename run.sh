#!/bin/bash

# Function to detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &> /dev/null; then
            echo "debian"
        elif command -v yum &> /dev/null; then
            echo "rhel"
        elif command -v pacman &> /dev/null; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to install packages based on OS
install_packages() {
    local os_type=$1
    
    case $os_type in
        "debian")
            echo "Detected Debian/Ubuntu system"
            echo "Updating package list..."
            sudo apt update
            echo "Upgrading packages..."
            sudo apt upgrade -y
            
            echo "Installing Python3 and related packages..."
            sudo apt install -y python3 python3-pip python3-venv
            ;;
        "macos")
            echo "Detected macOS system"
            if ! command -v brew &> /dev/null; then
                echo "Homebrew not found. Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            
            echo "Installing Python3 and related packages..."
            brew install python3
            ;;
        "rhel")
            echo "Detected RHEL/CentOS system"
            sudo yum update -y
            sudo yum install -y python3 python3-pip python3-venv
            ;;
        "arch")
            echo "Detected Arch Linux system"
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm python python-pip python-virtualenv
            ;;
        *)
            echo "Unsupported operating system: $os_type"
            echo "Please install Python3, pip3, and python3-venv manually"
            ;;
    esac
}

# Function to check Python dependencies
check_python_deps() {
    if ! command -v python3 &> /dev/null; then
        echo "Python3 could not be found"
        return 1
    fi
    
    if ! command -v pip3 &> /dev/null; then
        echo "Pip3 could not be found"
        return 1
    fi
    
    # Check if virtual environment module is available
    python3 -c "import venv" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Python3 venv module could not be found"
        return 1
    fi
    
    return 0
}

# Function to setup virtual environment
setup_venv() {
    if [ ! -d "venv" ]; then
        echo "Virtual environment not found. Creating one..."
        python3 -m venv venv
    fi
    
    echo "Activating virtual environment..."
    source venv/bin/activate
    
    echo "Upgrading pip..."
    pip install --upgrade pip
    
    echo "Installing dependencies..."
    pip install -r requirements.txt
}

# Main execution
main() {
    echo "Detecting operating system..."
    OS_TYPE=$(detect_os)
    echo "Detected OS: $OS_TYPE"
    
    echo "Installing/updating system packages..."
    install_packages $OS_TYPE
    
    echo "Checking Python dependencies..."
    if ! check_python_deps; then
        echo "Python dependencies check failed. Exiting."
        exit 1
    fi
    
    echo "Setting up virtual environment..."
    setup_venv
    
    echo "Starting Django server..."
    cd evilpunch && python manage.py migrate && python manage.py runserver
}

# Run main function
main


