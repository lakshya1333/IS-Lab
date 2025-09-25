# RSA DIGITAL SIGNATURE SERVER
# Generates RSA key pair, signs a message, and sends signature to client for verification
# Demonstrates digital signature creation and transmission

import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Server configuration
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Port number

def main():
    """
    Main server function: Generate keys, create signature, send to client
    """
    # Generate RSA key pair for digital signatures
    # 2048-bit key provides good security for signatures
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,    # Standard public exponent (2^16 + 1)
        key_size=2048            # 2048-bit key size
    )
    server_public_key = server_private_key.public_key()  # Derive public key

    # Message to be signed (in real applications, this could be any data)
    message = b"Important message from server"
    
    # Create digital signature using RSA-PSS (Probabilistic Signature Scheme)
    signature = server_private_key.sign(
        message,                  # Data to sign
        padding.PSS(              # PSS padding scheme (more secure than PKCS#1 v1.5)
            mgf=padding.MGF1(hashes.SHA256()),  # Mask Generation Function with SHA-256
            salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length for security
        ),
        hashes.SHA256()           # Hash algorithm for signature
    )

    # Serialize public key to PEM format for transmission
    # Client needs public key to verify signature
    public_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Start server and send signature data to client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))      # Bind to address and port
        s.listen(1)               # Listen for one connection
        print(f"[SERVER] Listening on {HOST}:{PORT}...")
        
        conn, addr = s.accept()   # Accept client connection
        with conn:
            print(f"[SERVER] Connected by {addr}")

            # Send public key (length-prefixed for reliable parsing)
            conn.sendall(len(public_key_pem).to_bytes(4, 'big'))  # Send length as 4 bytes
            conn.sendall(public_key_pem)                          # Send public key data

            # Send message (length-prefixed)
            conn.sendall(len(message).to_bytes(4, 'big'))         # Send message length
            conn.sendall(message)                                 # Send message data

            # Send signature (length-prefixed)
            conn.sendall(len(signature).to_bytes(4, 'big'))       # Send signature length
            conn.sendall(signature)                               # Send signature data

            print("[SERVER] Sent public key, message, and signature")

# DIGITAL SIGNATURE PROCESS (SERVER SIDE):
# 1. Generate RSA key pair (private key kept secret, public key shared)
# 2. Create message to be signed
# 3. Compute hash of message using SHA-256
# 4. Encrypt hash with private key using RSA-PSS padding → signature
# 5. Send public key, message, and signature to client

# RSA-PSS (Probabilistic Signature Scheme):
# - More secure than deterministic PKCS#1 v1.5 signatures
# - Uses random salt to prevent signature forgery attacks
# - Same message produces different signatures each time (probabilistic)
# - Provides existential unforgeability under chosen message attacks

# SECURITY PROPERTIES:
# - Authentication: Proves message came from holder of private key
# - Non-repudiation: Signer cannot deny creating the signature
# - Integrity: Any change to message invalidates signature
# - Private key must be kept secret; public key can be shared

if __name__ == "__main__":
    main()