# ASYMMETRIC CRYPTOGRAPHY SUITE
# Implements RSA, ElGamal, ECC (ECIES), and Diffie-Hellman key exchange
# Requires: pycryptodome, cryptography

from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import os

# cryptography library imports for ECC & modern DH
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# =========================================
# RSA (Rivest-Shamir-Adleman) Cryptosystem
# =========================================
# Public Key: (n, e), Private Key: (n, d)
# Security: Based on difficulty of factoring large composite numbers

def rsa_generate(bits=2048):
    """
    Generate RSA key pair with specified bit length
    Args: bits (int) - key size in bits (1024, 2048, 3072, 4096)
    Returns: dict with private key, public key, and internal values (p, q, n, e, d, phi)
    
    RSA Key Generation Process:
    1. Choose two large primes p and q
    2. Compute n = p × q (modulus)
    3. Compute φ(n) = (p-1)(q-1) (Euler's totient)
    4. Choose e such that gcd(e, φ(n)) = 1 (public exponent, usually 65537)
    5. Compute d = e^(-1) mod φ(n) (private exponent)
    """
    priv = RSA.generate(bits)  # Generate RSA keypair using PyCryptodome
    pub = priv.publickey()     # Extract public key component
    
    # Expose internal values for educational purposes
    n = priv.n      # Modulus (n = p × q)
    e = priv.e      # Public exponent (usually 65537)
    d = priv.d      # Private exponent (d = e^(-1) mod φ(n))
    p = priv.p      # First prime factor
    q = priv.q      # Second prime factor
    phi = (p - 1) * (q - 1)  # Euler's totient function φ(n)
    
    return {
        "priv": priv, "pub": pub,
        "n": n, "e": e, "d": d, "p": p, "q": q, "phi": phi
    }

def rsa_encrypt(pubkey, message_bytes):
    """
    RSA encryption using OAEP padding (secure padding scheme)
    Args: pubkey (RSA public key object), message_bytes (bytes)
    Returns: encrypted ciphertext (bytes)
    
    Process: C = M^e mod n (with OAEP padding for security)
    """
    from Crypto.Cipher import PKCS1_OAEP  # Optimal Asymmetric Encryption Padding
    cipher = PKCS1_OAEP.new(pubkey)       # Create cipher with OAEP padding
    return cipher.encrypt(message_bytes)   # Encrypt with padding

def rsa_decrypt(privkey, ciphertext):
    """
    RSA decryption using OAEP padding
    Args: privkey (RSA private key object), ciphertext (bytes)
    Returns: decrypted plaintext (bytes)
    
    Process: M = C^d mod n (with OAEP padding removal)
    """
    from Crypto.Cipher import PKCS1_OAEP
    cipher = PKCS1_OAEP.new(privkey)      # Create cipher with same padding
    return cipher.decrypt(ciphertext)      # Decrypt and remove padding

# =========================================
# ElGamal Cryptosystem
# =========================================
# Based on discrete logarithm problem in finite fields
# Public Key: (p, g, y), Private Key: (p, g, x) where y = g^x mod p

def elgamal_generate(bits=2048):
    """
    Generate ElGamal key pair
    Args: bits (int) - size of prime p in bits
    Returns: dict with public and private key components
    
    ElGamal Key Generation:
    1. Choose large prime p
    2. Choose generator g (primitive root mod p)
    3. Choose private key x randomly from [2, p-2]
    4. Compute public key y = g^x mod p
    """
    p = number.getPrime(bits)              # Generate large prime p
    g = 2                                  # Generator (simplified for demo)
    x = number.getRandomRange(2, p-1)      # Private key x (random)
    y = pow(g, x, p)                       # Public key y = g^x mod p
    
    pub = {"p": p, "g": g, "y": y}         # Public key (p, g, y)
    priv = {"p": p, "g": g, "x": x}        # Private key (p, g, x)
    return {"pub": pub, "priv": priv}

def elgamal_encrypt(pub, plaintext_bytes):
    """
    ElGamal encryption
    Args: pub (public key dict), plaintext_bytes (bytes)
    Returns: tuple (c1, c2) representing ciphertext
    
    ElGamal Encryption Process:
    1. Convert message to integer m
    2. Choose random ephemeral key k
    3. Compute c1 = g^k mod p
    4. Compute shared secret s = y^k mod p  
    5. Compute c2 = m × s mod p
    """
    m = bytes_to_long(plaintext_bytes)     # Convert bytes to integer
    p, g, y = pub["p"], pub["g"], pub["y"] # Extract public key components
    k = number.getRandomRange(2, p-2)      # Random ephemeral key k
    
    c1 = pow(g, k, p)                      # c1 = g^k mod p
    s = pow(y, k, p)                       # Shared secret s = y^k mod p
    c2 = (m * s) % p                       # c2 = m × s mod p
    return (c1, c2)                        # Return ciphertext pair

def elgamal_decrypt(priv, ciphertext):
    """
    ElGamal decryption
    Args: priv (private key dict), ciphertext (tuple c1, c2)
    Returns: decrypted plaintext (bytes)
    
    ElGamal Decryption Process:
    1. Compute shared secret s = c1^x mod p
    2. Compute s^(-1) mod p (modular inverse)
    3. Recover message m = c2 × s^(-1) mod p
    """
    c1, c2 = ciphertext                    # Extract ciphertext components
    p, x = priv["p"], priv["x"]            # Extract private key components
    
    s = pow(c1, x, p)                      # Shared secret s = c1^x mod p
    s_inv = inverse(s, p)                  # Modular inverse of s
    m = (c2 * s_inv) % p                   # Recover message m
    return long_to_bytes(m)                # Convert integer back to bytes

# =========================================
# ECC (Elliptic Curve Cryptography) with ECIES
# =========================================
# ECIES = Elliptic Curve Integrated Encryption Scheme
# Combines ECDH key agreement + symmetric encryption

def ecc_generate(curve_name="SECP256R1"):
    """
    Generate ECC key pair on specified elliptic curve
    Args: curve_name (str) - elliptic curve name (SECP256R1, SECP384R1, etc.)
    Returns: dict with private key object and public key bytes
    
    Common Curves:
    - SECP256R1 (P-256): 256-bit security, widely used
    - SECP384R1 (P-384): 384-bit security
    - SECP521R1 (P-521): 521-bit security (highest)
    """
    curve = getattr(ec, curve_name)()      # Get curve object by name
    priv = ec.generate_private_key(curve, default_backend())  # Generate private key
    pub = priv.public_key()                # Derive public key
    
    # Serialize public key to bytes (uncompressed point format)
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return {"priv": priv, "pub_bytes": pub_bytes}

def ecc_derive_shared(priv, peer_pub_bytes):
    """
    Derive shared secret using ECDH (Elliptic Curve Diffie-Hellman)
    Args: priv (private key object), peer_pub_bytes (peer's public key bytes)
    Returns: 32-byte derived symmetric key
    
    ECDH Process:
    1. Load peer's public key from bytes
    2. Perform ECDH: shared_point = private_key × peer_public_key
    3. Derive symmetric key from shared point using HKDF
    """
    # Reconstruct peer's public key from bytes
    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, peer_pub_bytes)
    shared = priv.exchange(ec.ECDH(), peer_pub)  # ECDH key agreement
    
    # Derive AES key using HKDF (HMAC-based Key Derivation Function)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),          # Hash algorithm for KDF
        length=32,                          # Output 256-bit (32-byte) key
        salt=None,                          # No salt (optional)
        info=b"ecdh derived key",           # Context info
        backend=default_backend()
    ).derive(shared)
    return derived_key

def ecc_encrypt_ecies(recipient_pub_bytes, plaintext):
    """
    ECIES encryption: Ephemeral ECDH + AES-GCM
    Args: recipient_pub_bytes (recipient's public key), plaintext (bytes)
    Returns: dict with ephemeral public key, nonce, and AES-GCM ciphertext
    
    ECIES Process:
    1. Generate ephemeral key pair
    2. Perform ECDH with recipient's public key
    3. Derive symmetric key from shared secret
    4. Encrypt plaintext with AES-GCM using derived key
    """
    # Load recipient's public key (assume SECP256R1 curve)
    curve = ec.SECP256R1()
    recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, recipient_pub_bytes)

    # Generate ephemeral (one-time) key pair
    eph_priv = ec.generate_private_key(curve, default_backend())
    eph_pub = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Derive shared secret and symmetric encryption key
    shared = eph_priv.exchange(ec.ECDH(), recipient_pub)
    key = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b"ecies", 
        backend=default_backend()
    ).derive(shared)

    # Encrypt with AES-GCM (provides authenticity + confidentiality)
    aesgcm = AESGCM(key)                   # Create AES-GCM cipher
    nonce = os.urandom(12)                 # 96-bit random nonce for GCM
    ct = aesgcm.encrypt(nonce, plaintext, None)  # Encrypt (returns ciphertext||tag)
    
    return {"ephemeral_pub": eph_pub_bytes, "nonce": nonce, "ciphertext": ct}

def ecc_decrypt_ecies(recipient_priv, bundle):
    """
    ECIES decryption: Reverse of encryption process
    Args: recipient_priv (recipient's private key), bundle (encryption output dict)
    Returns: decrypted plaintext (bytes)
    
    ECIES Decryption:
    1. Extract ephemeral public key from bundle
    2. Perform ECDH with ephemeral public key
    3. Derive same symmetric key as sender
    4. Decrypt AES-GCM ciphertext
    """
    eph_pub_bytes = bundle["ephemeral_pub"]  # Extract ephemeral public key
    nonce = bundle["nonce"]                  # Extract nonce
    ct = bundle["ciphertext"]                # Extract ciphertext + tag
    
    # Derive symmetric key using recipient's private key
    curve = recipient_priv.curve
    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, eph_pub_bytes)
    shared = recipient_priv.exchange(ec.ECDH(), peer_pub)  # Same shared secret
    key = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b"ecies", 
        backend=default_backend()
    ).derive(shared)
    
    # Decrypt AES-GCM (automatically verifies authentication tag)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)     # Decrypt and verify
    return pt

# =========================================
# Diffie-Hellman Key Exchange (Classic)
# =========================================
# Allows two parties to establish shared secret over insecure channel
# Security based on discrete logarithm problem

def dh_parameters_generate(key_size=2048):
    """
    Generate DH domain parameters (p, g)
    Args: key_size (int) - size of prime p in bits
    Returns: DH parameters object
    
    DH Parameters:
    - p: large prime modulus
    - g: generator (primitive root mod p)
    These can be shared publicly and reused
    """
    params = dh.generate_parameters(
        generator=2,                        # Use 2 as generator (common choice)
        key_size=key_size,                  # Size of prime p
        backend=default_backend()
    )
    return params

def dh_generate_keypair(params):
    """
    Generate DH key pair given domain parameters
    Args: params (DH parameters object)
    Returns: (private_key_object, public_key_bytes)
    
    DH Key Generation:
    1. Choose random private key x from [1, p-1]
    2. Compute public key y = g^x mod p
    """
    priv = params.generate_private_key()    # Generate random private key
    pub = priv.public_key()                 # Compute corresponding public key
    
    # Serialize public key to PEM format for transmission
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_bytes

def dh_shared_key(priv, peer_pub_bytes):
    """
    Compute DH shared secret and derive symmetric key
    Args: priv (own private key), peer_pub_bytes (peer's public key in PEM)
    Returns: 32-byte derived symmetric key
    
    DH Key Agreement:
    1. Compute shared secret = peer_public^own_private mod p
    2. Both parties compute same value: (g^a)^b = (g^b)^a = g^(ab) mod p
    3. Derive symmetric key from shared secret using HKDF
    """
    # Load peer's public key from PEM bytes
    peer_pub = serialization.load_pem_public_key(peer_pub_bytes, backend=default_backend())
    shared = priv.exchange(peer_pub)        # Compute shared secret (raw bytes)
    
    # Derive symmetric key from shared secret using HKDF
    key = HKDF(
        algorithm=hashes.SHA256(), 
        length=32,                          # 256-bit symmetric key
        salt=None, 
        info=b"dh derived", 
        backend=default_backend()
    ).derive(shared)
    return key

# =========================================
# DEMONSTRATION EXAMPLES
# =========================================

# RSA Example: Alice encrypts message for Bob
print("=== RSA Example ===")
rsa = rsa_generate(2048)
cipher = rsa_encrypt(rsa["pub"], b"hello rsa")
print("RSA Ciphertext:", cipher.hex()[:32], "...")
plain = rsa_decrypt(rsa["priv"], cipher)
print("RSA Decrypted:", plain)

# ElGamal Example: Probabilistic encryption
print("\n=== ElGamal Example ===")
eg = elgamal_generate(1024)
c = elgamal_encrypt(eg["pub"], b"msg")
print("ElGamal Ciphertext:", c)
print("ElGamal Decrypted:", elgamal_decrypt(eg["priv"], c))

# ECC ECIES Example: Modern elliptic curve encryption
print("\n=== ECC ECIES Example ===")
alice = ecc_generate()
bob = ecc_generate()
# Alice encrypts message for Bob
bundle = ecc_encrypt_ecies(bob["pub_bytes"], b"secret message")
# Bob decrypts Alice's message
pt = ecc_decrypt_ecies(bob["priv"], bundle)
print("ECC ECIES Decrypted:", pt)

# Diffie-Hellman Example: Key exchange
print("\n=== Diffie-Hellman Example ===")
params = dh_parameters_generate(2048)
a_priv, a_pub_bytes = dh_generate_keypair(params)
b_priv, b_pub_bytes = dh_generate_keypair(params)
# Both parties compute the same shared key
ka = dh_shared_key(a_priv, b_pub_bytes)
kb = dh_shared_key(b_priv, a_pub_bytes)
assert ka == kb  # Verify both parties derived same key
print("DH Shared Key Match:", ka == kb)
