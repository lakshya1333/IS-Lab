# HASH-BASED INTEGRITY VERIFICATION SERVER
# Receives data from client, computes SHA-256 hash, and sends back hash
# Demonstrates data integrity verification over network

import socket
import hashlib

# Server configuration
HOST = '127.0.0.1'  # localhost (loopback address)
PORT = 65432        # Port number for server to listen on

def compute_hash(data):
    """
    Compute SHA-256 hash of input data
    Args: data (bytes) - input data to hash
    Returns: hex string representation of hash
    
    SHA-256 produces 256-bit (32-byte) hash digest
    """
    sha = hashlib.sha256()  # Create SHA-256 hash object
    sha.update(data)        # Process the input data
    return sha.hexdigest()  # Return hash as hexadecimal string

def main():
    """
    Main server function: Listen for client connections and process data
    """
    # Create TCP socket (SOCK_STREAM = TCP, AF_INET = IPv4)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))          # Bind socket to address and port
        s.listen()                    # Start listening for connections
        print(f"Server listening on {HOST}:{PORT}")

        # Accept incoming connection
        conn, addr = s.accept()       # Wait for client connection
        with conn:
            print('Connected by', addr)
            
            # Receive data from client (up to 1024 bytes at once)
            data = conn.recv(1024)
            if not data:              # No data received
                return

            print(f"Received data: {data}")

            # Optional: Uncomment next line to simulate data tampering/corruption
            # This would cause hash verification to fail on client side
            #data = data + b'corrupted'

            # Compute hash of received data
            hash_value = compute_hash(data)
            print(f"Computed hash: {hash_value}")

            # Send computed hash back to client for verification
            conn.sendall(hash_value.encode())  # Convert hash string to bytes

# INTEGRITY VERIFICATION PROCESS:
# 1. Client sends original data to server
# 2. Server computes hash of received data  
# 3. Server sends hash back to client
# 4. Client computes hash of original data locally
# 5. Client compares local hash with server hash
# 6. If hashes match → data was transmitted without corruption
# 7. If hashes differ → data was corrupted or tampered with

# SECURITY NOTES:
# - This demonstrates integrity checking, not authentication
# - Real applications should use HMAC or digital signatures
# - SHA-256 is cryptographically secure hash function
# - Any change to data will result in completely different hash

if __name__ == "__main__":
    main()