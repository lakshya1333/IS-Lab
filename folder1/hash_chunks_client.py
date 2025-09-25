# CHUNKED DATA HASH VERIFICATION CLIENT
# Sends data in small chunks to simulate streaming/large file transmission
# Verifies data integrity using hash comparison after chunked transmission

import socket
import hashlib
import time

# Server connection configuration
HOST = '127.0.0.1'  # Server IP address (localhost)
PORT = 65432        # Server port number

def compute_hash(data: bytes) -> str:
    """
    Compute SHA-256 hash of complete data
    Args: data (bytes) - complete data to hash
    Returns: hex string representation of hash
    """
    return hashlib.sha256(data).hexdigest()

def main():
    """
    Main client function: Send data in chunks and verify integrity
    """
    # Get message from user
    message = input("Enter the message to send: ")
    message_bytes = message.encode()  # Convert to bytes for transmission

    # Split message into small chunks (10 bytes each for demonstration)
    chunk_size = 10
    chunks = [message_bytes[i:i+chunk_size] for i in range(0, len(message_bytes), chunk_size)]

    # Connect to server and send chunked data
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        # Send data in chunks with small delays
        for i, chunk in enumerate(chunks):
            print(f"Sending chunk {i+1}/{len(chunks)}: {chunk}")
            s.sendall(chunk)           # Send current chunk
            time.sleep(0.1)            # Small delay to simulate streaming/network latency

        # Signal end of data transmission
        s.shutdown(socket.SHUT_WR)     # Close write side (no more data to send)

        # Receive hash computed by server from complete reconstructed message
        hash_received = s.recv(1024).decode()
        print(f"Hash received from server: {hash_received}")

        # Compute hash locally using original complete message
        local_hash = compute_hash(message_bytes)
        print(f"Local computed hash: {local_hash}")

        # Compare hashes for integrity verification
        if hash_received == local_hash:
            print("Integrity check PASSED: hashes match.")
            print("✓ All chunks were received correctly and data is intact")
        else:
            print("Integrity check FAILED: hashes do NOT match!")
            print("✗ Data corruption detected during chunked transmission")

# CHUNKED TRANSMISSION BENEFITS:
# 1. Memory efficiency: Don't need to load entire file in memory
# 2. Progressive transmission: Can start sending before all data ready
# 3. Error recovery: Can retransmit individual chunks if needed
# 4. Flow control: Can pace transmission based on receiver capacity
# 5. Parallel processing: Server can process chunks as they arrive

# INTEGRITY VERIFICATION WORKFLOW:
# 1. Client splits message into small chunks
# 2. Client sends chunks sequentially with delays
# 3. Server receives and buffers all chunks
# 4. Server reconstructs complete message from chunks
# 5. Server computes hash of reconstructed message
# 6. Client computes hash of original complete message
# 7. Hash comparison confirms successful chunked transmission

# REAL-WORLD APPLICATIONS:
# - File upload/download with progress tracking
# - Video/audio streaming with integrity checking
# - Database replication with verification
# - Backup systems with corruption detection
# - Software updates with package verification

if __name__ == "__main__":
    main()