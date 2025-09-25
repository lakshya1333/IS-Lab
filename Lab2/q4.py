from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# -------------------------------------------------------
# Triple DES Encryption / Decryption
# -------------------------------------------------------
pt = "Classified Text"  # Plaintext message

# Key for Triple DES: must be 16 or 24 bytes (128 or 192 bits)
# DES3.adjust_key_parity ensures the key satisfies DES parity requirements
k = "1234567890ABCDEF9876543210FEDCBA5555AAAA3333CCCC"  # Hex key
key = bytes.fromhex(k)
key = DES3.adjust_key_parity(key)

block_size = 8  # DES block size is 8 bytes

# -------------------------------
# Create Triple DES cipher
# -------------------------------
# MODE_ECB: simplest mode, encrypts blocks independently
cipher = DES3.new(key, DES3.MODE_ECB)

# -------------------------------
# Padding
# -------------------------------
padded_message = pad(pt.encode(), block_size)  # Pad message to multiple of 8 bytes

# -------------------------------
# Encryption
# -------------------------------
ct = cipher.encrypt(padded_message)
print(f"Ciphertext (hex): {ct.hex()}")

# -------------------------------
# Decryption
# -------------------------------
mes = unpad(cipher.decrypt(ct), block_size).decode()
print(f"Decrypted Message: {mes}")

# -------------------------------
# Verification
# -------------------------------
print(f"\nVerification: {pt == mes}")

# -------------------------------------------------------
# Variations you can try:
# -------------------------------------------------------
# 1. Modes of operation:
#    - DES3.MODE_CBC: Cipher Block Chaining, requires an IV
#    - DES3.MODE_CFB: Cipher Feedback (stream mode)
#    - DES3.MODE_OFB: Output Feedback (stream mode)
#    - DES3.MODE_CTR: Counter mode (no padding required)
#
# 2. Key variations:
#    - 16-byte key (two-key Triple DES)
#    - 24-byte key (three-key Triple DES)
#    - Use DES3.adjust_key_parity for any new keys
#
# 3. Padding variations:
#    - You can use PKCS7 (pad/unpad from Crypto.Util.Padding)
#    - Or implement your own padding scheme
#
# 4. Hex vs bytes input:
#    - You can input key as raw bytes or hex string
