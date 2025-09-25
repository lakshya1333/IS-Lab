# # 4. Encrypt the message "Secure Communication" using DES in Cipher Block Chaining
# # (CBC) mode with the key "A1B2C3D4" and an initialization vector (IV) of "12345678".
# Provide the ciphertext and then decrypt it to retrieve the original message.

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Parameters
key = b"A1B2C3D4"          # 8-byte DES key
iv = b"12345678"           # 8-byte IV
message = b"Secure Communication"
block_size = 8             # DES block size = 8 bytes

# --- Encryption ---
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(message, block_size))
print("Ciphertext (hex):", ciphertext.hex())

# --- Decryption ---
decipher = DES.new(key, DES.MODE_CBC, iv)
plaintext = unpad(decipher.decrypt(ciphertext), block_size)
print("Decrypted message:", plaintext.decode())
