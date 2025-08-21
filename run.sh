#!/bin/bash

# Default mode
MODE="development"

# Function to show usage
show_usage() {
    echo "Usage: $0 [-p|--production] [-d|--development] [-h|--help]"
    echo ""
    echo "Options:"
    echo "  -p, --production   Run in production mode using Gunicorn"
    echo "  -d, --development  Run in development mode using Django runserver (default)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                 # Run in development mode (default)"
    echo "  $0 -d              # Run in development mode"
    echo "  $0 -p              # Run in production mode"
    echo "  $0 --production    # Run in production mode"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--production)
            MODE="production"
            shift
            ;;
        -d|--development)
            MODE="development"
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

echo "Starting EvilPunch in $MODE mode..."

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
            sudo apt install -y python3 python3-pip python3-venv certbot
            ;;
        "macos")
            echo "Detected macOS system"
            if ! command -v brew &> /dev/null; then
                echo "Homebrew not found. Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            
            echo "Installing Python3 and related packages..."
            brew install python3
            brew install certbot
            ;;
        "rhel")
            echo "Detected RHEL/CentOS system"
            sudo yum update -y
            sudo yum install -y python3 python3-pip python3-venv certbot
            ;;
        "arch")
            echo "Detected Arch Linux system"
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm python python-pip python-virtualenv certbot
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

# Function to check OpenSSL dependencies
check_openssl_deps() {
    if ! command -v openssl &> /dev/null; then
        echo "OpenSSL could not be found. Installing OpenSSL..."
        local os_type=$1
        
        case $os_type in
            "debian")
                sudo apt install -y openssl libssl-dev
                ;;
            "macos")
                brew install openssl
                ;;
            "rhel")
                sudo yum install -y openssl openssl-devel
                ;;
            "arch")
                sudo pacman -S --noconfirm openssl
                ;;
            *)
                echo "Unsupported operating system for OpenSSL installation: $os_type"
                echo "Please install OpenSSL manually"
                return 1
                ;;
        esac
        
        # Verify installation
        if ! command -v openssl &> /dev/null; then
            echo "OpenSSL installation failed"
            return 1
        fi
    fi
    
    echo "OpenSSL is available"
    return 0
}

# Function to check and create server SSL directory and certificates
check_server_ssl() {
    local ssl_dir="server_ssl"
    
    # Check if server_ssl directory exists, if not create it
    if [ ! -d "$ssl_dir" ]; then
        echo "Server SSL directory not found. Creating $ssl_dir directory..."
        mkdir -p "$ssl_dir"
    fi
    
    # Check if server SSL certificate exists, if not create it
    if [ ! -f "$ssl_dir/server.crt" ] || [ ! -f "$ssl_dir/server.key" ]; then
        echo "Server SSL certificate not found. Generating self-signed certificate..."
        
        # Generate private key
        openssl genrsa -out "$ssl_dir/server.key" 2048
        
        # Generate certificate signing request
        openssl req -new -key "$ssl_dir/server.key" -out "$ssl_dir/server.csr" -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        # Generate self-signed certificate
        openssl x509 -req -days 365 -in "$ssl_dir/server.csr" -signkey "$ssl_dir/server.key" -out "$ssl_dir/server.crt"
        
        # Clean up CSR file
        rm "$ssl_dir/server.csr"
        
        echo "Server SSL certificate generated successfully"
    else
        echo "Server SSL certificate already exists"
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
    
    # Install Gunicorn for production mode
    if [ "$MODE" = "production" ]; then
        echo "Installing Gunicorn for production mode..."
        pip install gunicorn
    fi
}

# Function to start development server
start_development_server() {
    echo "Starting Django development server..."
    cd evilpunch && python manage.py migrate && python manage.py ensure_admin_user && python manage.py runserver
}

# Function to start production server
start_production_server() {
    echo "Starting Gunicorn production server..."
    
    # Check SSL certificates
    SSL_DIR="server_ssl"
    CERT_FILE="$SSL_DIR/server.crt"
    KEY_FILE="$SSL_DIR/server.key"
    
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        echo "✓ SSL certificates found - HTTPS/SSL will be enabled"
        echo "  Certificate: $CERT_FILE"
        echo "  Private Key: $KEY_FILE"
    else
        echo "⚠ SSL certificates not found - Server will run in HTTP mode"
        echo "  To enable SSL, ensure both files exist in $SSL_DIR:"
        echo "    - server.crt (SSL certificate)"
        echo "    - server.key (private key)"
    fi
    
    cd evilpunch && python manage.py migrate && python manage.py ensure_admin_user && gunicorn --config gunicorn.conf.py evilpunch.wsgi:application
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

    echo "Checking OpenSSL dependencies..."
    if ! check_openssl_deps $OS_TYPE; then
        echo "OpenSSL dependencies check failed. Exiting."
        exit 1
    fi
    
    echo "Checking server SSL setup..."
    if ! check_server_ssl; then
        echo "Server SSL setup failed. Exiting."
        exit 1
    fi
    
    echo "Setting up virtual environment..."
    setup_venv
    
    # Start server based on mode
    if [ "$MODE" = "production" ]; then
        start_production_server
    else
        start_development_server
    fi
}

# Run main function
main


