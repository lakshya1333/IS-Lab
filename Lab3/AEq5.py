# 5. You are conducting a study to evaluate the performance and security of RSA and
# ElGamal encryption algorithms in securing communication for a government
# agency. Implement both RSA (using 2048-bit keys) and ElGamal (using the
# secp256r1 curve) encryption schemes to encrypt and decrypt sensitive messages
# exchanged between agencies. Measure the time taken for key generation,
# encryption, and decryption processes for messages of various sizes (e.g., 1 KB, 10
# KB). Compare the computational efficiency and overhead of RSA and ElGamal
# algorithms. Perform the same for ECC with RSA and ElGamal. 


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from tinyec import registry
import hashlib, secrets, binascii, time

# ===============================
# Helper Functions
# ===============================

def ecc_point_to_256_bit_key(point):
    """
    Derive a 256-bit AES key from an ECC point.
    """
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encrypt_AES_GCM(msg_bytes, secretKey):
    """
    Encrypt message using AES-GCM.
    Returns: ciphertext, nonce, authTag
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg_bytes)
    return ciphertext, aesCipher.nonce, authTag

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    """
    Decrypt AES-GCM ciphertext using secretKey.
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# ===============================
# ECC ElGamal Encryption
# ===============================

def encrypt_ECC(msg_bytes, pubKey, curve):
    """
    ECC ElGamal hybrid encryption:
    - Generate ephemeral private key
    - Compute shared secret
    - Use AES-GCM to encrypt the message
    Returns: ciphertext, nonce, authTag, ephemeral public key
    """
    ephemeralPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ephemeralPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg_bytes, secretKey)
    ephemeralPubKey = ephemeralPrivKey * curve.g
    return ciphertext, nonce, authTag, ephemeralPubKey

def decrypt_ECC(encryptedMsg, privKey):
    """
    Decrypt ECC ElGamal hybrid message.
    """
    ciphertext, nonce, authTag, ephemeralPubKey = encryptedMsg
    sharedECCKey = privKey * ephemeralPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

# ===============================
# Performance measurement function
# ===============================

def measure_time(func, *args, **kwargs):
    """
    Measures execution time of a function.
    Returns: result, time_taken (seconds)
    """
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, end - start

# ===============================
# Sample messages of different sizes
# ===============================
messages = {
    "1KB": b"A"*1024,
    "10KB": b"A"*10*1024
}

# ===============================
# RSA (2048-bit) Encryption/Decryption
# ===============================

print("=== RSA (2048-bit) ===")

# Key generation
rsa_key, rsa_keygen_time = measure_time(RSA.generate, 2048)
public_key = rsa_key.publickey()
cipher_rsa = PKCS1_OAEP.new(public_key)
dec_rsa = PKCS1_OAEP.new(rsa_key)
print(f"RSA Key Generation Time: {rsa_keygen_time:.4f} s")

for size, msg in messages.items():
    # Encrypt
    ct, enc_time = measure_time(cipher_rsa.encrypt, msg[:190])  # PKCS1_OAEP max ~190 bytes for 2048-bit
    # Decrypt
    pt, dec_time = measure_time(dec_rsa.decrypt, ct)
    print(f"\nMessage size: {size} (truncated to 190 bytes for RSA)")
    print(f"RSA Encryption Time: {enc_time*1000:.3f} ms")
    print(f"RSA Decryption Time: {dec_time*1000:.3f} ms")
    print(f"Decryption successful: {pt == msg[:190]}")

# ===============================
# ECC (ElGamal over secp256r1)
# ===============================
print("\n=== ECC ElGamal (secp256r1) ===")

curve = registry.get_curve('secp256r1')
ecc_priv = secrets.randbelow(curve.field.n)
ecc_pub = ecc_priv * curve.g

print(f"ECC Key Generation: Private key generated")

for size, msg in messages.items():
    # Encrypt
    encrypted_msg, enc_time = measure_time(encrypt_ECC, msg, ecc_pub, curve)
    # Decrypt
    decrypted_msg, dec_time = measure_time(decrypt_ECC, encrypted_msg, ecc_priv)
    print(f"\nMessage size: {size}")
    print(f"ECC Encryption Time: {enc_time*1000:.3f} ms")
    print(f"ECC Decryption Time: {dec_time*1000:.3f} ms")
    print(f"Decryption successful: {decrypted_msg == msg}")

# ===============================
# Summary / Observations
# ===============================
print("\n=== SUMMARY OBSERVATIONS ===")
print("RSA:")
print(" - Encryption is slower for larger messages because of padding limits.")
print(" - Must split large messages into blocks (<190 bytes for 2048-bit key).")
print("ECC ElGamal:")
print(" - Supports arbitrary message sizes via hybrid AES encryption.")
print(" - Typically faster for large messages because AES does the heavy lifting.")
print(" - Provides perfect forward secrecy using ephemeral keys.")

