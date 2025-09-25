from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# -------------------------------------------------------
# AES-192 Encryption / Decryption Demo
# -------------------------------------------------------
pt = "Top Secret Data"  # Plaintext message

# AES-192 requires 24-byte key (192 bits)
k = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
key = bytes.fromhex(k)

print(f"Plaintext: {pt}")
print(f"Key (hex): {k}")
print(f"AES Mode: AES-192")

# -------------------------------
# Create AES cipher in ECB mode
# -------------------------------
cipher = AES.new(key, AES.MODE_ECB)

# -------------------------------
# Padding
# -------------------------------
p = pad(pt.encode(), AES.block_size)  # AES block size is 16 bytes
print(f"Padded Message (bytes): {p}")
print(f"Padded length: {len(p)} bytes")

# -------------------------------
# AES Encryption Steps Explanation
# -------------------------------
print(f"\nENCRYPTION PROCESS")
print(f"1. Key Expansion: 192-bit key expanded to 13 round keys (AES-192 has 12 rounds + initial AddRoundKey)")
print(f"2. Initial Round: AddRoundKey with round key 0")
print(f"3. Main Rounds: 11 rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey)")
print(f"4. Final Round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)")

# -------------------------------
# Encryption
# -------------------------------
ct = cipher.encrypt(p)  # Encrypt padded plaintext
print(f"\nCiphertext (hex): {ct.hex()}")
print(f"Ciphertext length: {len(ct)} bytes")

# -------------------------------
# Decryption & Verification
# -------------------------------
print(f"\nDECRYPTION VERIFICATION")
mes = unpad(cipher.decrypt(ct), AES.block_size).decode()  # Remove padding after decryption
print(f"Decrypted Message: {mes}")
print(f"\nVerification: {pt == mes}")  # Check correctness

# -------------------------------------------------------
# Notes on AES-192 internal steps (handled by Crypto library):
# -------------------------------------------------------
# - Key Expansion: Original 24-byte key generates 13 round keys (one for initial AddRoundKey + 12 rounds)
# - Initial Round: AddRoundKey (XOR plaintext block with round key 0)
# - Main Rounds: Each round does:
#       1. SubBytes: Non-linear substitution of each byte using S-box
#       2. ShiftRows: Rotate rows of state matrix
#       3. MixColumns: Linear transformation mixing bytes in each column
#       4. AddRoundKey: XOR with round key
# - Final Round: Same as main rounds but without MixColumns
# - Padding ensures the message length is multiple of 16 bytes
# - Mode ECB: Each block encrypted independently (not secure for multiple blocks in practice)
