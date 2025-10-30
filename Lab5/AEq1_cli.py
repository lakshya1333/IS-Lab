import socket
import hashlib
import time

# Client setup
HOST = '127.0.0.1'  # server IP
PORT = 5001         # port number

# Create TCP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Message to send (split into parts)
message = "Hello server, this is a multi-part message for integrity testing."
parts = [message[i:i+10] for i in range(0, len(message), 10)]  # split into 10-char chunks

# Send each part separately
for part in parts:
    print(f"[>] Sending part: {part}")
    client_socket.sendall(part.encode())
    time.sleep(0.2)  # small delay to simulate chunked transmission

# Send 'END' to signal completion
client_socket.sendall("END".encode())

# Compute local hash
local_hash = hashlib.sha256(message.encode()).hexdigest()

# Receive server hash
server_hash = client_socket.recv(1024).decode()

print(f"\n[>] Local Hash:  {local_hash}")
print(f"[>] Server Hash: {server_hash}")

# Verify message integrity
if local_hash == server_hash:
    print("[✓] Data integrity verified! No corruption detected.")
else:
    print("[✗] Message corrupted or tampered during transmission!")

client_socket.close()
