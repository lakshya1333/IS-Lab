# RSA DIGITAL SIGNATURE CLIENT
# Receives public key, message, and signature from server, then verifies signature
# Demonstrates digital signature verification process

import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Server connection configuration
HOST = '127.0.0.1'  # Server IP address
PORT = 65432        # Server port number

def recv_exact(sock, n):
    """
    Receive exactly n bytes from socket (handles partial receives)
    Args: sock (socket) - network socket
          n (int) - exact number of bytes to receive
    Returns: bytes data of exact length n
    Raises: ConnectionError if connection closes unexpectedly
    
    TCP sockets may return fewer bytes than requested in recv(),
    so this function ensures we get exactly the amount we need.
    """
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))  # Receive remaining bytes
        if not packet:                     # Connection closed
            raise ConnectionError("Connection closed unexpectedly")
        data += packet                     # Accumulate received data
    return data

def main():
    """
    Main client function: Receive signature data and verify authenticity
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))  # Connect to server

        # Receive public key (length-prefixed format)
        public_key_len = int.from_bytes(recv_exact(s, 4), 'big')  # First 4 bytes = length
        public_key_pem = recv_exact(s, public_key_len)           # Receive public key data
        # Parse PEM-encoded public key
        public_key = serialization.load_pem_public_key(public_key_pem)

        # Receive message (length-prefixed format)
        message_len = int.from_bytes(recv_exact(s, 4), 'big')     # Message length
        message = recv_exact(s, message_len)                     # Message data

        # Receive signature (length-prefixed format)
        signature_len = int.from_bytes(recv_exact(s, 4), 'big')  # Signature length
        signature = recv_exact(s, signature_len)                 # Signature data

        # Verify digital signature using server's public key
        try:
            public_key.verify(
                signature,                # The signature to verify
                message,                  # Original message that was signed
                padding.PSS(              # Same PSS padding as used for signing
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()           # Same hash algorithm as used for signing
            )
            verified = True               # Verification successful
        except InvalidSignature:
            verified = False              # Verification failed

        # Display results
        print(f"message: {message.decode()}")
        print(f"signature (hex): {signature.hex()[:64]}...")  # Show first 64 chars of signature
        print(f"verified: {'verified' if verified else 'NOT verified'}")

# DIGITAL SIGNATURE VERIFICATION PROCESS (CLIENT SIDE):
# 1. Receive public key, message, and signature from server
# 2. Use public key to decrypt signature → recovered hash
# 3. Compute hash of received message using same algorithm (SHA-256)  
# 4. Compare recovered hash with computed hash
# 5. If hashes match → signature is valid (authentication successful)
# 6. If hashes differ → signature is invalid (authentication failed)

# VERIFICATION SECURITY:
# - Only holder of private key could create valid signature
# - Public key cryptographically confirms signature authenticity
# - Any tampering with message or signature causes verification failure
# - Cannot forge signatures without private key (computationally infeasible)

# PRACTICAL APPLICATIONS:
# - Software updates: Verify packages haven't been tampered with
# - Email security: Confirm sender identity and message integrity
# - Document signing: Legal/business document authentication
# - Certificate authorities: Root of trust for web security (HTTPS)
# - Code signing: Verify software comes from trusted developer

# ATTACK SCENARIOS PREVENTED:
# - Man-in-the-middle: Attacker cannot forge valid signatures
# - Message tampering: Any change invalidates signature
# - Replay attacks: Each signature tied to specific message content
# - Impersonation: Only private key holder can create valid signatures

if __name__ == "__main__":
    main()