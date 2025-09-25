# ECC + AES-GCM hybrid encryption example
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

# Step 1: Define plaintext message
pt = "Secure Transactions"

# Step 2: Choose the elliptic curve
curve = registry.get_curve('brainpoolP256r1')  # 256-bit curve

# Step 3: Convert an ECC point into a 256-bit AES key
def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

# Step 4: AES-GCM encryption
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)  # AES in Galois/Counter Mode
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)  # Encrypt + generate auth tag
    return (ciphertext, aesCipher.nonce, authTag)

# Step 5: AES-GCM decryption
def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)  # Verify auth tag
    return plaintext

# Step 6: ECC-based hybrid encryption
def encrypt_ECC(msg, pubKey):
    # Generate random private key for this ciphertext
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    # Compute shared ECC key
    sharedECCKey = ciphertextPrivKey * pubKey
    # Derive 256-bit AES key from shared ECC point
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    # Encrypt message using AES-GCM
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    # Compute public key corresponding to the ephemeral private key
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

# Step 7: ECC-based hybrid decryption
def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    # Recompute shared ECC key
    sharedECCKey = privKey * ciphertextPubKey
    # Derive AES key from ECC point
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    # Decrypt the message
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

# Step 8: Generate ECC key pair for recipient
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

# Step 9: Display keys and plaintext
print(f"Plaintext: {pt}")
print(f"Private key: {hex(privKey)}")
print(f"Public key (x): {hex(pubKey.x)}")
print(f"Public key (y): {hex(pubKey.y)}")
print(f"Curve: {curve.name}")

# Step 10: Encrypt the message
encryptedMsg = encrypt_ECC(pt.encode(), pubKey)
ct = binascii.hexlify(encryptedMsg[0]).decode()
print(f"Ciphertext (hex): {ct}")
print(f"Nonce (hex): {binascii.hexlify(encryptedMsg[1]).decode()}")
print(f"Auth Tag (hex): {binascii.hexlify(encryptedMsg[2]).decode()}")

# Step 11: Decrypt the message
mes = decrypt_ECC(encryptedMsg, privKey).decode()
print(f"Decrypted message: {mes}")

# Step 12: Verify correctness
print(f"Original == Decrypted: {pt == mes}")
