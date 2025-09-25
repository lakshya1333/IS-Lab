# 5. Encrypt the message "Cryptography Lab Exercise" using AES in Counter (CTR)
# mode with the key "0123456789ABCDEF0123456789ABCDEF" and a nonce of
# "0000000000000000". Provide the ciphertext and then decrypt it to retrieve the original
# message.


from Crypto.Cipher import AES
from Crypto.Util import Counter

# --- Parameters ---
key = b"0123456789ABCDEF0123456789ABCDEF"  # 32-byte key for AES-256
message = b"Cryptography Lab Exercise"

# Nonce as integer (8 bytes = 64 bits)
nonce_int = 0

# Create counter: 64-bit prefix (nonce), 64-bit counter
ctr = Counter.new(64, prefix=nonce_int.to_bytes(8, byteorder='big'), initial_value=0)

# --- Encryption ---
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
ciphertext = cipher.encrypt(message)
print("Ciphertext (hex):", ciphertext.hex())

# --- Decryption (reset counter!) ---
ctr_dec = Counter.new(64, prefix=nonce_int.to_bytes(8, byteorder='big'), initial_value=0)
decipher = AES.new(key, AES.MODE_CTR, counter=ctr_dec)
plaintext = decipher.decrypt(ciphertext)
print("Decrypted message:", plaintext.decode())
