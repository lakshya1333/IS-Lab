# lab_crypto_demo.py
# Demonstrates RSA, ElGamal, Rabin, and Diffie-Hellman
# Alice encrypts -> Bob decrypts for each scheme.
#
# Requires: pycryptodome, cryptography

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os

# ---------------------
# RSA (using PyCryptodome)
# ---------------------
def rsa_keygen(bits=2048):
    """Generate RSA private & public key objects."""
    priv = RSA.generate(bits)            # private key (includes p,q,d,n,e)
    pub = priv.publickey()               # public key
    return priv, pub

def rsa_encrypt(pubkey, plaintext_bytes):
    """Encrypt bytes using RSA-OAEP with public key."""
    cipher = PKCS1_OAEP.new(pubkey)     # OAEP padding (secure)
    return cipher.encrypt(plaintext_bytes)

def rsa_decrypt(privkey, ciphertext):
    """Decrypt RSA-OAEP ciphertext bytes with private key."""
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext)

def demo_rsa():
    print("\n=== RSA Demo ===")
    # Key generation (Bob will be receiver)
    bob_priv, bob_pub = rsa_keygen(2048)
    # Alice's plaintext
    alice_msg = b"Hello Bob - RSA"
    # Alice encrypts with Bob's public key
    ciphertext = rsa_encrypt(bob_pub, alice_msg)
    print("Alice -> Bob (ciphertext length):", len(ciphertext))
    # Bob decrypts with his private key
    plaintext = rsa_decrypt(bob_priv, ciphertext)
    print("Bob decrypted:", plaintext)


# ---------------------
# ElGamal (integer-based)
# ---------------------
def elgamal_keygen(bits=1024):
    """Generate ElGamal public/private keys (integer version)."""
    # p should be a large prime; g a generator. For lab/demo we use getPrime.
    p = number.getPrime(bits)
    g = 2                                 # choose small g (demo only)
    x = number.getRandomRange(2, p-2)     # private key x
    y = pow(g, x, p)                      # public key y = g^x mod p
    pub = {"p": p, "g": g, "y": y}
    priv = {"p": p, "g": g, "x": x}
    return pub, priv

def elgamal_encrypt(pub, plaintext_bytes):
    """ElGamal encrypt: returns tuple (c1, c2) where both are integers."""
    p, g, y = pub["p"], pub["g"], pub["y"]
    # Simple padding: append a fixed trailer so receiver can disambiguate if needed
    m_int = bytes_to_long(plaintext_bytes + b"@@")  # convert to integer
    if m_int >= p:
        raise ValueError("Plaintext too long for chosen p (use larger p or shorter msg).")
    k = number.getRandomRange(2, p-2)               # ephemeral secret
    c1 = pow(g, k, p)                               # g^k mod p
    s = pow(y, k, p)                                # shared secret y^k mod p
    c2 = (m_int * s) % p                            # m * s mod p
    return (c1, c2)

def elgamal_decrypt(priv, ciphertext):
    """ElGamal decrypt: (c1,c2) -> plaintext bytes."""
    p, x = priv["p"], priv["x"]
    c1, c2 = ciphertext
    s = pow(c1, x, p)                               # s = c1^x mod p
    s_inv = inverse(s, p)                           # modular inverse of s
    m_int = (c2 * s_inv) % p
    plain = long_to_bytes(m_int)
    # remove trailer if present
    if plain.endswith(b"@@"):
        plain = plain[:-2]
    return plain

def demo_elgamal():
    print("\n=== ElGamal Demo ===")
    # Bob generates ElGamal keys (receiver)
    bob_pub, bob_priv = elgamal_keygen(1024)
    alice_msg = b"Hello Bob - ElGamal"
    # Alice encrypts to Bob
    c1, c2 = elgamal_encrypt(bob_pub, alice_msg)
    print("Alice -> Bob (c1,c2 sizes):", len(long_to_bytes(c1)), len(long_to_bytes(c2)))
    # Bob decrypts
    pt = elgamal_decrypt(bob_priv, (c1, c2))
    print("Bob decrypted:", pt)


# ---------------------
# Rabin Cryptosystem
# ---------------------
def rabin_keygen(bits=512):
    """Generate Rabin keys: p, q primes congruent to 3 mod 4, and n = p*q."""
    # helper to get prime p ≡ 3 (mod 4)
    def get_prime_3mod4(bits_half):
        while True:
            p = number.getPrime(bits_half)
            if p % 4 == 3:
                return p
    p = get_prime_3mod4(bits // 2)
    q = get_prime_3mod4(bits // 2)
    n = p * q
    pub = {"n": n}
    priv = {"p": p, "q": q}
    return pub, priv

def rabin_encrypt(pub, plaintext_bytes):
    """Rabin encrypt: c = m^2 mod n. Use small trailer to disambiguate on decrypt."""
    n = pub["n"]
    # Add small trailer to help choose correct root on decrypt (lab-friendly)
    m_int = bytes_to_long(plaintext_bytes + b"##")
    if m_int >= n:
        raise ValueError("Plaintext too long for modulus n.")
    c = pow(m_int, 2, n)
    return c

def rabin_decrypt(priv, ciphertext):
    """Rabin decrypt: returns list of four candidate plaintexts (bytes).
       We'll try to pick the one with the trailer '##' for convenience."""
    p, q = priv["p"], priv["q"]
    n = p * q
    c = ciphertext
    # compute square roots modulo p and q (p,q ≡ 3 mod 4 -> use pow(c, (p+1)/4, p))
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    # combine via CRT to get 4 roots
    # CRT helper: find x s.t. x % p = a1 and x % q = a2
    def crt(a1, a2):
        # solve x = a1 (mod p), x = a2 (mod q)
        inv_p_mod_q = inverse(p, q)
        t = ((a2 - a1) * inv_p_mod_q) % q
        return (a1 + p * t) % n

    r1 = crt(mp, mq)
    r2 = n - r1
    r3 = crt(mp, n - mq)
    r4 = n - r3

    candidates = [long_to_bytes(r) for r in (r1, r2, r3, r4)]
    # try to find trailer '##'
    for cnd in candidates:
        if cnd.endswith(b"##"):
            return cnd[:-2]   # strip trailer and return plaintext
    # If trailer not found, return all candidates for analysis
    return candidates

def demo_rabin():
    print("\n=== Rabin Demo ===")
    # Bob generates Rabin keys
    bob_pub, bob_priv = rabin_keygen(512) #512=keysize in bits
    alice_msg = b"Hello Bob - Rabin"
    # Alice encrypts
    c = rabin_encrypt(bob_pub, alice_msg)
    print("Alice -> Bob (cipher int size bytes):", len(long_to_bytes(c)))
    # Bob decrypts (gets one chosen by trailer if present)
    pt = rabin_decrypt(bob_priv, c)
    print("Bob decrypted (or candidates):", pt)


# ---------------------
# Diffie-Hellman Key Exchange + AES-GCM symmetric demo
# ---------------------
from cryptography.hazmat.primitives.asymmetric import dh

def dh_parameters(key_size=2048):
    """Generate DH parameters (p, g)."""
    params = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
    return params

def dh_generate_keypair(params):
    """Generate DH private key and return its private object and serialized public bytes (PEM)."""
    priv = params.generate_private_key()
    pub = priv.public_key()
    # serialize public key to bytes (PEM)
    pub_bytes = pub.public_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub_bytes

def dh_derive_shared(priv, peer_pub_bytes):
    """Given own private key and peer public bytes (PEM), derive a symmetric key via HKDF."""
    peer_pub = serialization.load_pem_public_key(peer_pub_bytes, backend=default_backend())
    shared = priv.exchange(peer_pub)   # raw shared bytes
    # Derive a 32-byte key using HKDF-SHA256
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dh demo", backend=default_backend()).derive(shared)
    return key  # 32-byte symmetric key

def aes_gcm_encrypt(key, plaintext):
    """Encrypt plaintext bytes with AES-GCM (PyCryptodome) and return (nonce, ciphertext, tag)."""
    aes = AES.new(key, AES.MODE_GCM)          # 16-byte random nonce generated internally
    ct, tag = aes.encrypt_and_digest(plaintext)
    return aes.nonce, ct, tag

def aes_gcm_decrypt(key, nonce, ciphertext, tag):
    """Decrypt AES-GCM ciphertext with key and nonce; raises ValueError on auth fail."""
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = aes.decrypt_and_verify(ciphertext, tag)
    return pt

def demo_diffie_hellman():
    print("\n=== Diffie-Hellman Demo ===")
    # Generate DH parameters (shared by both parties)
    params = dh_parameters(2048)
    # Alice and Bob each create their keypairs
    a_priv, a_pub_bytes = dh_generate_keypair(params)
    b_priv, b_pub_bytes = dh_generate_keypair(params)

    # Each derives the same shared symmetric key
    a_key = dh_derive_shared(a_priv, b_pub_bytes)
    b_key = dh_derive_shared(b_priv, a_pub_bytes)
    assert a_key == b_key, "Derived keys do not match!"
    print("Derived symmetric key (hex):", a_key.hex()[:64], "...")

    # Alice uses derived key to encrypt a message for Bob using AES-GCM
    alice_msg = b"Hello Bob - via DH & AES-GCM"
    nonce, ct, tag = aes_gcm_encrypt(a_key, alice_msg)
    print("Alice -> Bob (AES-GCM ct len):", len(ct))
    print("Cipher text: ",ct)
    # Bob decrypts
    pt = aes_gcm_decrypt(b_key, nonce, ct, tag)
    print("Bob decrypted:", pt)


# ---------------------
# Run all demos
# ---------------------
if __name__ == "__main__":
    demo_rsa()
    demo_elgamal()
    demo_rabin()
    demo_diffie_hellman()
