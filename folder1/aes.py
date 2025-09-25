# AES (Advanced Encryption Standard) - Symmetric Block Cipher
# Demonstrates different modes of operation with 128-bit AES

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

# Generate random 128-bit AES key (16 bytes)
# AES supports: 128-bit (16 bytes), 192-bit (24 bytes), 256-bit (32 bytes)
key = get_random_bytes(16)

# Plaintext must be exactly 16 bytes for block modes (ECB/CBC)
# Stream modes (CFB/OFB/CTR) can handle any length
plaintext = b"HelloWorld123456"  # Exactly 16 bytes

print("Plaintext:", plaintext)

# ========================================
# 1. ECB (Electronic Code Book) Mode
# ========================================
# CHARACTERISTICS:
# - Each 16-byte block encrypted independently with same key
# - Same plaintext block → same ciphertext block (SECURITY WEAKNESS)
# - No IV needed, deterministic
# - Parallel encryption/decryption possible
# - NOT RECOMMENDED for most applications due to pattern leakage

cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher in ECB mode
ciphertext = cipher.encrypt(plaintext)  # Encrypt the plaintext
print("\nECB Ciphertext:", ciphertext)
# Decrypt: create new cipher object (ECB is stateless)
print("ECB Decrypted:", AES.new(key, AES.MODE_ECB).decrypt(ciphertext))

# ========================================
# 2. CBC (Cipher Block Chaining) Mode  
# ========================================
# CHARACTERISTICS:
# - Each block XORed with previous ciphertext before encryption
# - Requires random IV (Initialization Vector) for security
# - Same plaintext → different ciphertext (due to random IV)
# - Sequential encryption (can't parallelize), but parallel decryption
# - Most common mode for file encryption

iv = get_random_bytes(16)  # Random 16-byte IV for CBC
cipher = AES.new(key, AES.MODE_CBC, iv)  # IV must be provided
ciphertext = cipher.encrypt(plaintext)
print("\nCBC Ciphertext:", ciphertext)
# Decrypt: must use same IV that was used for encryption
print("CBC Decrypted:", AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))

# ========================================
# 3. CFB (Cipher Feedback) Mode
# ========================================
# CHARACTERISTICS:
# - Stream cipher mode - encrypts bit by bit or byte by byte
# - Can handle any plaintext length (no padding required)
# - Self-synchronizing after errors
# - Sequential encryption and decryption
# - Good for encrypting streams of data

iv = get_random_bytes(16)  # Random IV required
cipher = AES.new(key, AES.MODE_CFB, iv)
ciphertext = cipher.encrypt(plaintext)  # Can encrypt any length
print("\nCFB Ciphertext:", ciphertext)
print("CFB Decrypted:", AES.new(key, AES.MODE_CFB, iv).decrypt(ciphertext))

# ========================================
# 4. OFB (Output Feedback) Mode
# ========================================
# CHARACTERISTICS:  
# - Stream cipher mode - generates keystream independent of plaintext
# - Can handle any plaintext length
# - Encryption and decryption are identical operations (XOR with keystream)
# - No error propagation - single bit error affects only that bit
# - Keystream can be precomputed

iv = get_random_bytes(16)  # Random IV required
cipher = AES.new(key, AES.MODE_OFB, iv)
ciphertext = cipher.encrypt(plaintext)
print("\nOFB Ciphertext:", ciphertext)
print("OFB Decrypted:", AES.new(key, AES.MODE_OFB, iv).decrypt(ciphertext))

# ========================================
# 5. CTR (Counter Mode)
# ========================================
# CHARACTERISTICS:
# - Stream cipher mode using counter that increments for each block
# - Can handle any plaintext length
# - Fully parallelizable for both encryption and decryption  
# - Random access - can decrypt any part without decrypting whole
# - Counter must never repeat with same key (nonce + counter)

ctr = Counter.new(128, initial_value=42)  # 128-bit counter starting at 42
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
ciphertext = cipher.encrypt(plaintext)

# IMPORTANT: Must reinitialize counter with same value for decryption
ctr = Counter.new(128, initial_value=42)  # Reset counter to same initial value
print("\nCTR Ciphertext:", ciphertext)
print("CTR Decrypted:", AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ciphertext))

# ========================================
# 6. GCM (Galois/Counter Mode) - AEAD
# ========================================
# CHARACTERISTICS:
# - Authenticated Encryption with Associated Data (AEAD)
# - Provides BOTH confidentiality (encryption) AND authenticity (authentication)
# - Generates authentication tag to verify integrity
# - Can authenticate additional data without encrypting it
# - Built-in protection against tampering
# - RECOMMENDED for modern applications

cipher = AES.new(key, AES.MODE_GCM)  # Auto-generates random nonce
ciphertext, tag = cipher.encrypt_and_digest(plaintext)  # Returns ciphertext + auth tag
nonce = cipher.nonce  # Save the auto-generated nonce for decryption
print("\nGCM Ciphertext:", ciphertext.hex())
print("GCM Tag:", tag)

# Decryption with integrity verification
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Use same nonce
decrypted = cipher.decrypt_and_verify(ciphertext, tag)  # Verifies tag automatically
print("GCM Decrypted:", decrypted)

# SECURITY NOTES:
# - ECB: Never use for sensitive data (patterns visible)
# - CBC: Good for files, requires proper IV handling  
# - CFB/OFB: Good for streams, requires unique IVs
# - CTR: Excellent performance, requires unique counter values
# - GCM: Best choice for new applications (encryption + authentication)
