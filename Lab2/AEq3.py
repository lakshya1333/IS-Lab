from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# -------------------------------------------------------
# AES-256 Key
# -------------------------------------------------------
# AES-256 requires a 32-byte key (256 bits)
# Here we use a hex-like ASCII string for demonstration
key = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

# -------------------------------------------------------
# Plaintext message
# -------------------------------------------------------
message = b"Encryption Strength"
block_size = 16  # AES block size = 128 bits

# -------------------------------------------------------
# Create AES cipher in ECB mode
# -------------------------------------------------------
# ECB = Electronic Codebook mode (each block encrypted independently)
cipher = AES.new(key, AES.MODE_ECB)

# -------------------------------------------------------
# Encryption
# -------------------------------------------------------
# Pad plaintext to multiple of block size before encryption
ciphertext = cipher.encrypt(pad(message, block_size))
print("Ciphertext (hex):", ciphertext.hex())

# -------------------------------------------------------
# Decryption
# -------------------------------------------------------
# Create new cipher object for decryption (same key and mode)
decipher = AES.new(key, AES.MODE_ECB)

# Decrypt and remove padding to get original plaintext
plaintext = unpad(decipher.decrypt(ciphertext), block_size)
print("Decrypted message:", plaintext.decode())

# -------------------------------------------------------
# Notes / Variations:
# -------------------------------------------------------
# 1. Modes of operation:
#    - ECB: Simple but not secure for repeated blocks
#    - CBC: Uses IV, better for long messages
#    - CFB / OFB / CTR: Stream-like operation, allows partial encryption
#
# 2. Padding:
#    - pad/unpad ensures message length is multiple of block size
#    - PKCS7 padding is default
#
# 3. Key:
#    - AES-256 requires exactly 32 bytes
#    - Can generate random keys: `get_random_bytes(32)`
#
# 4. Security:
#    - ECB leaks patterns in repeated plaintext blocks
#    - For secure encryption of real data, prefer CBC or CTR mode with random IV
