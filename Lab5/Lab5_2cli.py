# 2. Using socket programming in Python, demonstrate the application of hash functions
# for ensuring data integrity during transmission over a network. Write server and client
# scripts where the server computes the hash of received data and sends it back to the
# client, which then verifies the integrity of the data by comparing the received hash with
# the locally computed hash. Show how the hash verification detects data corruption
# or tampering during transmission.


import socket
import hashlib

# Client configuration
HOST = '127.0.0.1'  # server IP
PORT = 5000         # server port

# Create a TCP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Message to send
message = "This is a test message for integrity check"

# Send message to the server
client_socket.sendall(message.encode())

# Compute local hash
local_hash = hashlib.sha256(message.encode()).hexdigest()

# Receive hash from server
server_hash = client_socket.recv(1024).decode()

print(f"[>] Local Hash:  {local_hash}")
print(f"[>] Server Hash: {server_hash}")

# Verify integrity
if local_hash == server_hash:
    print("[✓] Data integrity verified! No corruption detected.")
else:
    print("[✗] Data corrupted or tampered during transmission!")

client_socket.close()
