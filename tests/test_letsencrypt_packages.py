#!/usr/bin/env python3
"""
Test script to verify Let's Encrypt SSL package dependencies
"""

def test_packages():
    """Test if all required packages can be imported"""
    packages = {}
    
    try:
        import acme
        packages['acme'] = acme.__version__
        print(f"✓ acme: {acme.__version__}")
    except ImportError as e:
        packages['acme'] = f"ERROR: {e}"
        print(f"✗ acme: {e}")
    
    try:
        import cryptography
        packages['cryptography'] = cryptography.__version__
        print(f"✓ cryptography: {cryptography.__version__}")
    except ImportError as e:
        packages['cryptography'] = f"ERROR: {e}"
        print(f"✗ cryptography: {e}")
    
    try:
        import requests
        packages['requests'] = requests.__version__
        print(f"✓ requests: {requests.__version__}")
    except ImportError as e:
        packages['requests'] = f"ERROR: {e}"
        print(f"✗ requests: {e}")
    
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        print("✓ cryptography.x509 modules")
    except ImportError as e:
        print(f"✗ cryptography.x509 modules: {e}")
    
    # Check if all packages are available
    all_good = all('ERROR' not in str(v) for v in packages.values())
    
    if all_good:
        print("\n🎉 All packages are available! Let's Encrypt SSL should work.")
        return True
    else:
        print("\n❌ Some packages are missing. Please install them with:")
        print("pip install acme cryptography requests")
        return False

if __name__ == "__main__":
    print("Testing Let's Encrypt SSL package dependencies...\n")
    test_packages()
