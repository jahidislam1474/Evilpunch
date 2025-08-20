#!/bin/bash

# SSL-Enabled Production startup script for EvilPunch
# This script starts the application in production mode using Gunicorn with SSL

echo "Starting EvilPunch in production mode with SSL..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup first."
    exit 1
fi

# Check SSL certificates
SSL_DIR="../server_ssl"
CERT_FILE="$SSL_DIR/server.crt"
KEY_FILE="$SSL_DIR/server.key"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "❌ SSL certificates not found!"
    echo "  Certificate: $CERT_FILE"
    echo "  Private Key: $KEY_FILE"
    echo ""
    echo "This script requires SSL certificates to run."
    echo "Please ensure both files exist in the server_ssl directory."
    echo ""
    echo "You can either:"
    echo "  1. Run the regular production script: ./start_production.sh"
    echo "  2. Generate SSL certificates first"
    echo "  3. Use development mode: ../run.sh -d"
    exit 1
fi

echo "✓ SSL certificates found:"
echo "  Certificate: $CERT_FILE"
echo "  Private Key: $KEY_FILE"
echo "  Server will start with HTTPS/SSL enabled"
echo ""

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

# Start Gunicorn server with SSL
echo "🔒 Starting Gunicorn production server with SSL..."
echo "HTTPS will be available at the configured host:port"
echo "Press Ctrl+C to stop the server"
echo ""

gunicorn --config gunicorn.conf.py evilpunch.wsgi:application
