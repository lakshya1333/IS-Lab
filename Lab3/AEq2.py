# 2. Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure
# Transactions" with the public key. Then decrypt the ciphertext with the private key
# to verify the original message. 


from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

# Step 1: Define the plaintext message
pt = "Secure Transactions"

# Step 2: Choose an elliptic curve
curve = registry.get_curve('brainpoolP256r1')  # 256-bit curve

# Step 3: Convert an ECC point to a 256-bit AES key
def ecc_point_to_256_bit_key(point):
    """
    Derive a 256-bit AES key from an ECC point.
    """
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

# Step 4: AES-GCM encryption and decryption functions
def encrypt_AES_GCM(msg, secretKey):
    """
    Encrypt message using AES-GCM with a 256-bit key.
    Returns ciphertext, nonce, and authentication tag.
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return ciphertext, aesCipher.nonce, authTag

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    """
    Decrypt AES-GCM ciphertext and verify authentication tag.
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# Step 5: ECC-based hybrid encryption
def encrypt_ECC(msg, pubKey):
    """
    Encrypt message using ECC:
    - Generate ephemeral ECC key
    - Derive shared secret
    - Use shared secret to encrypt with AES-GCM
    Returns: ciphertext, nonce, authTag, ephemeral public key
    """
    ciphertextPrivKey = secrets.randbelow(curve.field.n)  # ephemeral private key
    sharedECCKey = ciphertextPrivKey * pubKey             # shared secret point
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)    # 256-bit AES key
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g        # ephemeral public key
    return ciphertext, nonce, authTag, ciphertextPubKey

# Step 6: ECC-based hybrid decryption
def decrypt_ECC(encryptedMsg, privKey):
    """
    Decrypt ECC hybrid encrypted message:
    - Recompute shared secret using private key
    - Use shared secret to decrypt AES-GCM ciphertext
    """
    ciphertext, nonce, authTag, ciphertextPubKey = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

# Step 7: Generate ECC key pair for recipient
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

# Step 8: Display key info
print(f"Plaintext: {pt}")
print(f"Private key: {hex(privKey)}")
print(f"Public key (x): {hex(pubKey.x)}")
print(f"Public key (y): {hex(pubKey.y)}")
print(f"Curve: {curve.name}")

# Step 9: Encrypt the message
encryptedMsg = encrypt_ECC(pt.encode(), pubKey)
ct_hex = binascii.hexlify(encryptedMsg[0]).decode()
nonce_hex = binascii.hexlify(encryptedMsg[1]).decode()
authTag_hex = binascii.hexlify(encryptedMsg[2]).decode()

print(f"\nCiphertext (hex): {ct_hex}")
print(f"Nonce (hex): {nonce_hex}")
print(f"Auth Tag (hex): {authTag_hex}")

# Step 10: Decrypt the message
mes = decrypt_ECC(encryptedMsg, privKey).decode()
print(f"Decrypted message: {mes}")

# Step 11: Verify correctness
print(f"Original == Decrypted: {pt == mes}")
