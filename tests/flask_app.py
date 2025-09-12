#!/usr/bin/env python3
"""
Flask app with SSL support that echoes back all request headers as HTTP response
"""

from flask import Flask, request, jsonify
import ssl
import os
import sys
from datetime import datetime

app = Flask(__name__)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def echo_headers(path):
    """
    Echo back all request headers and basic request information
    """
    # Get all headers
    headers = dict(request.headers)
    
    # Prepare response data
    response_data = {
        'timestamp': datetime.now().isoformat(),
        'method': request.method,
        'url': request.url,
        'path': path,
        'headers': headers,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'content_type': request.content_type,
        'content_length': request.content_length,
        'is_secure': request.is_secure,
        'host': request.host,
        'scheme': request.scheme
    }
    
    # Add query parameters if any
    if request.args:
        response_data['query_params'] = dict(request.args)
    
    # Add form data if any (for POST requests)
    if request.form:
        response_data['form_data'] = dict(request.form)
    
    # Add JSON data if any
    if request.is_json and request.get_json():
        response_data['json_data'] = request.get_json()
    
    return jsonify(response_data), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'ssl_enabled': True
    }), 200

def create_ssl_context():
    """Create SSL context with self-signed certificate"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # SSL certificates directory
    ssl_dir = '/Users/abhijeetyadav/Documents/EvilPunch/Evilpunch/server_ssl'
    
    # Try to load existing certificates from server_ssl directory
    # Check for common certificate file extensions
    cert_extensions = ['server.crt', 'server.pem', 'cert.pem', 'certificate.pem', 'fullchain.pem']
    key_extensions = ['server.key', 'private.key', 'key.pem', 'private.pem']
    
    cert_file = None
    key_file = None
    
    # Find certificate file
    for ext in cert_extensions:
        potential_cert = os.path.join(ssl_dir, ext)
        if os.path.exists(potential_cert):
            cert_file = potential_cert
            break
    
    # Find key file
    for ext in key_extensions:
        potential_key = os.path.join(ssl_dir, ext)
        if os.path.exists(potential_key):
            key_file = potential_key
            break
    
    if cert_file and key_file:
        print(f"Loading existing SSL certificates: {cert_file}, {key_file}")
        context.load_cert_chain(cert_file, key_file)
    else:
        print("SSL certificates not found. Generating self-signed certificates...")
        print(f"Creating SSL certificates in: {ssl_dir}")
        
        # Ensure SSL directory exists
        os.makedirs(ssl_dir, exist_ok=True)
        
        # Generate self-signed certificate
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EvilPunch Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write private key to file
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate to file
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"Generated SSL certificates: {cert_file}, {key_file}")
        context.load_cert_chain(cert_file, key_file)
    
    return context

def main():
    """Main function to run the Flask app with SSL"""
    port = int(os.environ.get('PORT', 8443))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"Starting Flask app with SSL support...")
    print(f"SSL certificates directory: /Users/abhijeetyadav/Documents/EvilPunch/Evilpunch/server_ssl")
    print(f"Server will be available at: https://{host}:{port}")
    print(f"Health check: https://{host}:{port}/health")
    print(f"Echo endpoint: https://{host}:{port}/")
    print("Press Ctrl+C to stop the server")
    
    try:
        # Create SSL context
        ssl_context = create_ssl_context()
        
        # Run the app with SSL
        app.run(
            host=host,
            port=port,
            ssl_context=ssl_context,
            debug=False,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

