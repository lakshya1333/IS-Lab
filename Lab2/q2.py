from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# -------------------------------------------------------
# AES-128 Encryption / Decryption Demo
# -------------------------------------------------------
def aes_encrypt_decrypt_demo():
    message = "Sensitive Information"
    key_hex = "0123456789ABCDEF0123456789ABCDEF"  # 16 bytes = 128 bits
    key = bytes.fromhex(key_hex)

    print("Original Message:", message)
    print("Key (hex):", key_hex)
    print("Key length:", len(key), "bytes")
    print()
    
    # -------------------------------
    # AES Modes of Operation
    # -------------------------------
    # 1. ECB (Electronic Codebook)
    #    - Simple, encrypts each block independently
    #    - Not recommended for repeated patterns (data leakage)
    # cipher = AES.new(key, AES.MODE_ECB)

    # 2. CBC (Cipher Block Chaining)
    #    - Each block XORed with previous ciphertext
    #    - Requires Initialization Vector (IV)
    #    - Secure for repeated patterns
    # from Crypto.Random import get_random_bytes
    # iv = get_random_bytes(16)
    # cipher = AES.new(key, AES.MODE_CBC, iv)

    # 3. CFB (Cipher Feedback)
    #    - Stream mode: can encrypt data smaller than block size
    #    - Requires IV
    # cipher = AES.new(key, AES.MODE_CFB, iv)

    # 4. OFB (Output Feedback)
    #    - Stream mode similar to CFB
    #    - Requires IV
    # cipher = AES.new(key, AES.MODE_OFB, iv)

    # 5. CTR (Counter Mode)
    #    - Converts block cipher to stream cipher using a counter
    #    - Does NOT require padding
    # from Crypto.Util import Counter
    # ctr = Counter.new(128)
    # cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    # For this demo, we’ll use ECB
    cipher = AES.new(key, AES.MODE_ECB)

    # -------------------------------
    # Prepare plaintext: bytes + padding
    # -------------------------------
    plaintext_bytes = message.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, AES.block_size)

    # -------------------------------
    # Encrypt
    # -------------------------------
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')
    print("=== ENCRYPTION ===")
    print("Plaintext (bytes):", plaintext_bytes)
    print("Padded plaintext (bytes):", padded_plaintext)
    print("Ciphertext (hex):", ciphertext_hex)
    print()

    # -------------------------------
    # Decrypt
    # -------------------------------
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted_bytes = unpad(decrypted_padded, AES.block_size)
    decrypted_message = decrypted_bytes.decode('utf-8')

    print("=== DECRYPTION ===")
    print("Decrypted bytes:", decrypted_bytes)
    print("Decrypted message:", decrypted_message)
    print()

    # -------------------------------
    # Verification
    # -------------------------------
    print("=== VERIFICATION ===")
    if decrypted_message == message:
        print("✓ SUCCESS: Original message matches decrypted message!")
    else:
        print("✗ FAILED: Messages don't match!")

    return ciphertext_hex, decrypted_message

ciphertext, decrypted = aes_encrypt_decrypt_demo()
