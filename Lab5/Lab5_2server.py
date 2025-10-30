import socket
import hashlib

# Server configuration
HOST = '127.0.0.1'  # localhost
PORT = 5000         # arbitrary non-privileged port

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"[*] Server listening on {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"[+] Connected by {addr}")

# Receive data from the client
data = conn.recv(1024).decode()

if not data:
    print("[-] No data received.")
else:
    print(f"[>] Received data: {data}")

    # Compute SHA-256 hash of received data
    hash_obj = hashlib.sha256(data.encode())
    data_hash = hash_obj.hexdigest()

    print(f"[>] Computed hash: {data_hash}")

    # Send hash back to client
    conn.sendall(data_hash.encode())

conn.close()
server_socket.close()
