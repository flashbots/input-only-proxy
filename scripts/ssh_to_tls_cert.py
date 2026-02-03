#!/usr/bin/env python3
"""
Convert SSH ed25519 private key to TLS certificate.
This preserves the same key material for authentication.
"""

import sys
import argparse
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import (
    load_ssh_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography import x509
from cryptography.x509.oid import NameOID


def convert_ssh_to_tls_cert(ssh_key_path, output_path):
    """Convert SSH ed25519 private key to TLS certificate with private key"""
    
    # Load SSH private key
    print(f"Loading SSH private key from: {ssh_key_path}")
    try:
        with open(ssh_key_path, "rb") as f:
            ssh_key_data = f.read()
        
        private_key = load_ssh_private_key(ssh_key_data, password=None)
        
        # Ensure it's an ed25519 key
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            print("Error: Key is not ed25519")
            return False
            
    except Exception as e:
        print(f"Error loading SSH key: {e}")
        return False
    
    # Export private key as PKCS8 PEM
    print("Converting to PKCS8 format...")
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    # Generate self-signed certificate
    print("Generating self-signed certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FlashBox"),
        x509.NameAttribute(NameOID.COMMON_NAME, "searcher-client"),
    ])
    
    try:
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, algorithm=None)  # ed25519 doesn't need hash algorithm
        
        cert_pem = cert.public_bytes(Encoding.PEM)
        
    except Exception as e:
        print(f"Error generating certificate: {e}")
        return False
    
    # Write combined PEM file (private key + certificate)
    print(f"Writing TLS certificate to: {output_path}")
    try:
        with open(output_path, "wb") as f:
            f.write(private_key_pem)
            f.write(cert_pem)
            
    except Exception as e:
        print(f"Error writing output file: {e}")
        return False
    
    # Display public key for verification  
    from cryptography.hazmat.primitives.serialization import PublicFormat
    public_key_der = private_key.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    print("Successfully converted SSH key to TLS certificate!")
    print(f"Certificate contains both private key and certificate.")
    print(f"Public key (hex): {public_key_der.hex()}")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Convert SSH ed25519 private key to TLS certificate"
    )
    parser.add_argument(
        "ssh_key", 
        help="Path to SSH ed25519 private key (e.g., ~/.ssh/id_ed25519)"
    )
    parser.add_argument(
        "output_cert",
        help="Output path for TLS certificate (e.g., client-cert.pem)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate SSH key without creating output file"
    )
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("Dry run mode: validating SSH key only...")
        try:
            with open(args.ssh_key, "rb") as f:
                private_key = load_ssh_private_key(f.read(), password=None)
            if isinstance(private_key, ed25519.Ed25519PrivateKey):
                print("✅ SSH key is valid ed25519 format")
                return 0
            else:
                print("❌ SSH key is not ed25519")
                return 1
        except Exception as e:
            print(f"❌ Error validating SSH key: {e}")
            return 1
    
    success = convert_ssh_to_tls_cert(args.ssh_key, args.output_cert)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
