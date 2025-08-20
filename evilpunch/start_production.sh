#!/bin/bash

# Production startup script for EvilPunch
# This script starts the application in production mode using Gunicorn

echo "Starting EvilPunch in production mode..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup first."
    exit 1
fi

# Check SSL certificates
SSL_DIR="../server_ssl"
CERT_FILE="$SSL_DIR/server.crt"
KEY_FILE="$SSL_DIR/server.key"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "✓ SSL certificates found:"
    echo "  Certificate: $CERT_FILE"
    echo "  Private Key: $KEY_FILE"
    echo "  Server will start with HTTPS/SSL enabled"
else
    echo "⚠ SSL certificates not found in $SSL_DIR"
    echo "  Certificate: $CERT_FILE"
    echo "  Private Key: $KEY_FILE"
    echo "  Server will start with HTTP only"
    echo ""
    echo "To enable SSL, ensure both files exist:"
    echo "  - server.crt (SSL certificate)"
    echo "  - server.key (private key)"
    echo ""
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Check if Gunicorn is installed
if ! python -c "import gunicorn" 2>/dev/null; then
    echo "Gunicorn not found. Installing..."
    pip install gunicorn
fi

# Run database migrations
echo "Running database migrations..."
python manage.py migrate

# Ensure admin user exists
echo "Setting up admin user..."
python manage.py ensure_admin_user

# Start Gunicorn server
echo "Starting Gunicorn production server..."
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "🔒 HTTPS/SSL mode enabled"
else
    echo "🌐 HTTP mode (no SSL)"
fi
echo "Press Ctrl+C to stop the server"
echo ""

gunicorn --config gunicorn.conf.py evilpunch.wsgi:application
