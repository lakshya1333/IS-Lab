# CHUNKED DATA HASH VERIFICATION SERVER
# Receives data in multiple chunks, reconstructs full message, computes hash
# Demonstrates integrity verification for streaming/large data transmission

import socket
import hashlib

# Server configuration
HOST = '127.0.0.1'  # localhost (loopback address)
PORT = 65432        # Port number for server to listen on

def compute_hash(data: bytes) -> str:
    """
    Compute SHA-256 hash of input data
    Args: data (bytes) - complete data to hash
    Returns: hex string representation of hash
    
    Type hints help clarify expected input/output types
    """
    return hashlib.sha256(data).hexdigest()  # One-liner version of hash computation

def main():
    """
    Main server function: Receive chunked data and verify integrity
    """
    # Create TCP socket for reliable data transmission
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))          # Bind to network address
        s.listen()                    # Start listening for connections
        print(f"Server listening on {HOST}:{PORT}")

        # Accept client connection
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # Receive data in chunks and reconstruct full message
            full_message = b''        # Buffer to accumulate all chunks
            while True:
                # Receive up to 1024 bytes at a time
                data = conn.recv(1024)
                if not data:          # Client closed connection (no more data)
                    break
                full_message += data  # Append chunk to full message

            print(f"Received full message: {full_message.decode()}")
            
            # Compute hash of complete reconstructed message
            hash_value = compute_hash(full_message)
            print(f"Computed hash: {hash_value}")

            # Send hash back to client for verification
            conn.sendall(hash_value.encode())

# CHUNKED TRANSMISSION SCENARIOS:
# 1. Large files that exceed single packet size
# 2. Streaming data (real-time audio/video)
# 3. Network with limited buffer sizes
# 4. Progressive data processing
# 5. Memory-constrained environments

# INTEGRITY VERIFICATION PROCESS:
# 1. Client sends data in multiple chunks
# 2. Server receives and buffers all chunks
# 3. Server reconstructs complete message
# 4. Server computes hash of full message
# 5. Client computes hash of original complete message
# 6. Hash comparison verifies no data lost or corrupted

# IMPORTANT CONSIDERATIONS:
# - Order of chunks must be preserved
# - All chunks must be received before hash computation
# - Hash is computed on complete data, not individual chunks
# - TCP guarantees ordered delivery and error detection
# - For UDP, would need sequence numbers and error handling

if __name__ == "__main__":
    main()