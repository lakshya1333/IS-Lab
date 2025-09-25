# 3. Try the same in a client server-based scenario and record your observation and
# analysis.

# client.py
import socket
import hashlib
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

# --- CLIENT LOGIC ---
HOST = "127.0.0.1"
PORT = 65433

# The same helper function to hash a message.
def hash_message(msg: bytes):
    return bytes_to_long(hashlib.sha256(msg).digest())

# Generates an RSA key pair.
def generate_keys(bits=2048):
    p, q = getPrime(bits//2), getPrime(bits//2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return ((n, e), (n, d)) # (public_key, private_key)

# Signs a message using the private key.
def sign(msg: bytes, private_key: tuple):
    n, d = private_key
    # Hash the message.
    msg_hash = hash_message(msg)
    # Encrypt the hash with the private key to create the signature.
    signature = pow(msg_hash, d, n)
    return signature

# --- EXECUTION ---
# 1. Generate keys for the client.
public_key, private_key = generate_keys()
print("Client generated RSA key pair.")

# 2. The message to sign and send.
message_to_send = b"payment authorized for transaction #12345"

# 3. Sign the message with the private key.
signature = sign(message_to_send, private_key)
print("Message signed with private key.")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # 4. Send the public key to the server so it can verify.
    n, e = public_key
    s.sendall(n.to_bytes(256, 'big'))
    s.sendall(e.to_bytes(16, 'big'))
    
    # 5. Send the actual message.
    s.sendall(message_to_send)
    
    # 6. Send the signature.
    s.sendall(signature.to_bytes(256, 'big'))
    print("Sent public key, message, and signature to server.")
    
    # 7. Wait for the server's verification result.
    result = s.recv(1024).decode()
    print(f"\nServer responded: {result}")