# HASH-BASED INTEGRITY VERIFICATION CLIENT
# Sends data to server, receives hash back, and verifies data integrity
# Demonstrates end-to-end integrity checking using SHA-256

import socket
import hashlib

# Server connection configuration
HOST = '127.0.0.1'  # Server IP address (localhost)
PORT = 65432        # Server port number

def compute_hash(data):
    """
    Compute SHA-256 hash of input data (same function as server)
    Args: data (bytes) - input data to hash
    Returns: hex string representation of hash
    """
    sha = hashlib.sha256()  # Create SHA-256 hash object
    sha.update(data)        # Process the input data
    return sha.hexdigest()  # Return hash as hexadecimal string

def main():
    """
    Main client function: Send data to server and verify integrity
    """
    # Get data from user and convert to bytes
    data = input("Enter data to send: ").encode()

    # Connect to server and send data
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))    # Connect to server
        s.sendall(data)            # Send data to server

        # Receive hash computed by server
        hash_from_server = s.recv(1024).decode()  # Receive hash as string
        print(f"Hash received from server: {hash_from_server}")

    # Compute hash locally using original data
    local_hash = compute_hash(data)
    print(f"Local hash: {local_hash}")

    # Compare hashes for integrity verification
    if local_hash == hash_from_server:
        print("Data integrity verified: hashes match!")
        print("✓ Data was transmitted without corruption")
    else:
        print("Data integrity check failed: hashes do NOT match!")
        print("✗ Data may have been corrupted or tampered with")

# INTEGRITY CHECK WORKFLOW:
# 1. Client computes hash of original data
# 2. Client sends data to server over network
# 3. Server receives data and computes hash
# 4. Server sends computed hash back to client  
# 5. Client compares server hash with local hash
# 6. Match = data integrity confirmed
# 7. Mismatch = data corruption detected

# HASH PROPERTIES USED:
# - Deterministic: Same input always produces same hash
# - Avalanche effect: Small input change = completely different hash
# - Fixed output size: SHA-256 always produces 256-bit (64 hex char) hash
# - One-way: Cannot reverse hash to get original data

# LIMITATIONS:
# - Only detects corruption/changes, not who made them
# - No authentication (anyone can compute hash)
# - For security, use HMAC or digital signatures instead

if __name__ == "__main__":
    main()