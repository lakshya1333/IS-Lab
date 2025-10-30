import socket
import hashlib

# Server setup
HOST = '127.0.0.1'   # localhost
PORT = 5001          # port number

# Create TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"[*] Server listening on {HOST}:{PORT}")

conn, addr = server_socket.accept()
print(f"[+] Connection established from {addr}")

# Receive message parts and reassemble
received_message = ""
while True:
    data = conn.recv(1024).decode()
    if not data:
        break
    if data == "END":
        break
    print(f"[>] Received part: {data}")
    received_message += data

# Compute SHA-256 hash of full message
hash_obj = hashlib.sha256(received_message.encode())
message_hash = hash_obj.hexdigest()

print(f"[>] Full reassembled message: {received_message}")
print(f"[>] Computed hash: {message_hash}")

# Send hash back to client
conn.sendall(message_hash.encode())

conn.close()
server_socket.close()
