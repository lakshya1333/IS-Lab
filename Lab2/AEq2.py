# 2. Encrypt the following block of data using DES with the key "A1B2C3D4E5F60708".
# The data to be encrypted is: Mathematica
# Block1:
# 54686973206973206120636f6e666964656e7469616c206d657373616765
# Block2:
# 416e64207468697320697320746865207365636f6e6420626c6f636b
# a. Provide the ciphertext for each block.
# b. Decrypt the ciphertext to retrieve the original plaintext blocks.



from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# -------------------------------------------------------
# DES Key
# -------------------------------------------------------
# DES requires a key of exactly 8 bytes (64 bits)
key = bytes.fromhex("A1B2C3D4E5F60708")
block_size = 8  # DES block size = 64 bits

# -------------------------------------------------------
# Data blocks to encrypt
# -------------------------------------------------------
# Each block is given in hexadecimal representation
block1 = bytes.fromhex(
    "54686973206973206120636f6e666964656e7469616c206d657373616765"
)  # "This is a confidential message"
block2 = bytes.fromhex(
    "416e64207468697320697320746865207365636f6e6420626c6f636b"
)  # "And this is the second block"

# -------------------------------------------------------
# Create DES cipher (ECB mode)
# -------------------------------------------------------
# ECB = Electronic Codebook mode (each block encrypted independently)
cipher = DES.new(key, DES.MODE_ECB)

# -------------------------------------------------------
# Encrypt each block
# -------------------------------------------------------
# Pad the data to a multiple of 8 bytes before encryption
ciphertext1 = cipher.encrypt(pad(block1, block_size))
ciphertext2 = cipher.encrypt(pad(block2, block_size))

print("Ciphertext Block1 (hex):", ciphertext1.hex())
print("Ciphertext Block2 (hex):", ciphertext2.hex())

# -------------------------------------------------------
# Decryption
# -------------------------------------------------------
# Create a new cipher object for decryption
decipher = DES.new(key, DES.MODE_ECB)

# Decrypt and remove padding to retrieve original plaintext
plaintext1 = unpad(decipher.decrypt(ciphertext1), block_size)
plaintext2 = unpad(decipher.decrypt(ciphertext2), block_size)

print("Decrypted Block1:", plaintext1.decode())
print("Decrypted Block2:", plaintext2.decode())

# -------------------------------------------------------
# Notes / Variations:
# -------------------------------------------------------
# 1. Modes of operation:
#    - ECB used here for simplicity
#    - Can try CBC, CFB, OFB with IVs for more security
#
# 2. Padding:
#    - Pad ensures that each block is a multiple of 8 bytes
#    - PKCS7 padding is default in Crypto.Util.Padding.pad
#
# 3. For larger messages:
#    - Split message into multiple blocks
#    - Encrypt each block sequentially (or use CBC)
#
# 4. Key variations:
#    - DES only supports 8-byte keys (56 effective bits)
#    - Triple DES (3DES) can increase security
