# 4. You are tasked with implementing a secure communication system for a healthcare
# organization to exchange sensitive patient information securely between doctors
# and hospitals. Implement the ElGamal encryption scheme to encrypt patient
# records and medical data, ensuring confidentiality during transmission. Generate
# public and private keys using the secp256r1 curve and use ElGamal encryption to
# encrypt patient data with the recipient's public key and decrypt it with the
# recipient's private key. Measure the performance of encryption and decryption
# processes for data of varying sizes.


from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, time, binascii

# ===============================
# Step 1: Define helper functions
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
    Encrypt message using AES-GCM with 256-bit key.
    Returns ciphertext, nonce, and authentication tag.
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg_bytes)
    return ciphertext, aesCipher.nonce, authTag

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    """
    Decrypt AES-GCM ciphertext and verify authentication tag.
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# ===============================
# Step 2: ECC-based ElGamal
# ===============================

def encrypt_ECC(msg_bytes, pubKey, curve):
    """
    ECC ElGamal encryption:
    - Generate ephemeral private key
    - Derive shared secret
    - Encrypt message using AES-GCM
    Returns ciphertext, nonce, authTag, ephemeral public key
    """
    ephemeralPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ephemeralPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg_bytes, secretKey)
    ephemeralPubKey = ephemeralPrivKey * curve.g
    return ciphertext, nonce, authTag, ephemeralPubKey

def decrypt_ECC(encryptedMsg, privKey):
    """
    ECC ElGamal decryption:
    - Compute shared secret
    - Decrypt AES-GCM ciphertext
    """
    ciphertext, nonce, authTag, ephemeralPubKey = encryptedMsg
    sharedECCKey = privKey * ephemeralPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

# ===============================
# Step 3: Key generation
# ===============================

curve = registry.get_curve('secp256r1')  # widely-used 256-bit curve

# Recipient's key pair (private and public)
recipientPrivKey = secrets.randbelow(curve.field.n)
recipientPubKey = recipientPrivKey * curve.g

print(f"Recipient Private Key: {hex(recipientPrivKey)}")
print(f"Recipient Public Key (x): {hex(recipientPubKey.x)}")
print(f"Recipient Public Key (y): {hex(recipientPubKey.y)}")
print(f"Curve: {curve.name}")

# ===============================
# Step 4: Sample patient data
# ===============================

patient_data_samples = [
    "Patient A: Blood Type O+, Allergy: None",
    "Patient B: Blood Type A-, Allergy: Penicillin",
    "Patient C: Extensive medical history, includes multiple visits, prescriptions, and lab reports."
]

# ===============================
# Step 5: Encrypt, decrypt and measure performance
# ===============================

for data in patient_data_samples:
    msg_bytes = data.encode()
    
    # Encrypt
    start_enc = time.perf_counter()
    encryptedMsg = encrypt_ECC(msg_bytes, recipientPubKey, curve)
    end_enc = time.perf_counter()
    
    ct_hex = binascii.hexlify(encryptedMsg[0]).decode()
    
    print("\n==========================")
    print(f"Patient Data: {data}")
    print(f"Ciphertext (hex): {ct_hex}")
    print(f"Encryption Time: {(end_enc - start_enc) * 1000:.3f} ms")
    
    # Decrypt
    start_dec = time.perf_counter()
    decrypted_bytes = decrypt_ECC(encryptedMsg, recipientPrivKey)
    end_dec = time.perf_counter()
    
    decrypted_msg = decrypted_bytes.decode()
    print(f"Decrypted Message: {decrypted_msg}")
    print(f"Decryption Time: {(end_dec - start_dec) * 1000:.3f} ms")
    print(f"Original == Decrypted: {data == decrypted_msg}")
