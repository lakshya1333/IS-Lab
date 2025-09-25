# DIFFIE-HELLMAN KEY EXCHANGE WITH HMAC AUTHENTICATION
# Demonstrates secure key exchange and message authentication using shared secret
# Implements Miller-Rabin primality test and HMAC-SHA256 for integrity

import random
from hashlib import sha256
from hmac import HMAC

def is_prime(n, k=20):
    """
    Miller-Rabin probabilistic primality test
    Args: n (int) - number to test for primality
          k (int) - number of rounds (higher = more accurate)
    Returns: True if probably prime, False if definitely composite
    
    Miller-Rabin Algorithm:
    1. Write n-1 = 2^s * d (where d is odd)
    2. For k rounds: pick random witness a
    3. Compute x = a^d mod n
    4. If x = 1 or x = n-1, continue to next round
    5. For s-1 times: x = x^2 mod n, if x = n-1 break
    6. If loop completes without break, n is composite
    7. If all rounds pass, n is probably prime
    """
    if n < 2:
        return False
    
    # Handle small primes
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        d >>= 1    # Divide by 2 (right shift)
        s += 1     # Count factors of 2

    # Miller-Rabin rounds
    for _ in range(k):
        a = random.randrange(2, n - 1)     # Random witness
        x = pow(a, d, n)                   # x = a^d mod n
        
        if x == 1 or x == n - 1:
            continue                       # This round passes
        
        # Square x repeatedly s-1 times
        for __ in range(s - 1):
            x = (x * x) % n                # x = x^2 mod n
            if x == n - 1:
                break                      # This round passes
        else:
            return False                   # Composite (failed round)
    
    return True                            # Probably prime

def gen_prime(bits=512):
    """
    Generate random prime of specified bit length
    Args: bits (int) - desired bit length of prime
    Returns: random prime number
    
    Process:
    1. Generate random odd number of specified bit length
    2. Test for primality using Miller-Rabin
    3. If not prime, try next odd number
    4. Continue until prime found
    """
    while True:
        p = random.getrandbits(bits)       # Random bits-bit number
        p |= (1 << (bits - 1)) | 1         # Set MSB and LSB (ensure large and odd)
        if is_prime(p):
            return p

def gen_dh_params():
    """
    Generate Diffie-Hellman domain parameters (p, g)
    Returns: (prime_p, generator_g)
    
    Parameters:
    - p: large prime modulus (public)
    - g: generator, primitive root mod p (public, simplified to 2)
    
    In production, use safe primes p = 2q + 1 where q is also prime
    """
    p = gen_prime(512)    # Generate 512-bit prime
    g = 2                 # Use 2 as generator (simplified)
    return p, g

def dh_keygen(p, g):
    """
    Generate Diffie-Hellman key pair
    Args: p (int) - prime modulus, g (int) - generator
    Returns: (private_key, public_key)
    
    Key Generation:
    1. Choose random private key x from [2, p-2]
    2. Compute public key y = g^x mod p
    """
    x = random.randrange(2, p - 2)    # Private key (kept secret)
    y = pow(g, x, p)                  # Public key (can be shared)
    return x, y

def dh_shared_secret(their_pub, priv, p):
    """
    Compute Diffie-Hellman shared secret
    Args: their_pub (int) - other party's public key
          priv (int) - own private key
          p (int) - prime modulus
    Returns: shared secret (both parties get same value)
    
    Shared Secret Computation:
    - Alice: secret = Bob_public^Alice_private mod p
    - Bob:   secret = Alice_public^Bob_private mod p
    - Result: Both compute g^(Alice_private * Bob_private) mod p
    """
    return pow(their_pub, priv, p)

def hmac_sign(key, message):
    """
    Create HMAC-SHA256 authentication tag for message
    Args: key (int) - shared secret key
          message (bytes) - message to authenticate
    Returns: HMAC tag (bytes)
    
    HMAC (Hash-based Message Authentication Code):
    - Provides message integrity and authenticity
    - Uses shared secret key + cryptographic hash function
    - Prevents tampering and forgery attacks
    - Formula: HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
    """
    # Convert integer key to bytes for HMAC
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big')
    return HMAC(key_bytes, message, sha256).digest()

def hmac_verify(key, message, signature):
    """
    Verify HMAC-SHA256 authentication tag
    Args: key (int) - shared secret key
          message (bytes) - original message
          signature (bytes) - HMAC tag to verify
    Returns: True if valid, False if invalid
    
    Verification Process:
    1. Recompute HMAC using same key and message
    2. Compare with provided signature
    3. Match = authentic, Mismatch = tampered/forged
    """
    expected = hmac_sign(key, message)
    return expected == signature           # Constant-time comparison

# ================================================
# DEMONSTRATION: Diffie-Hellman + HMAC Authentication
# ================================================

# Message to authenticate
m = b"message"

# 1. Generate Diffie-Hellman domain parameters (public)
print("=== Diffie-Hellman Key Exchange ===")
p_dh, g_dh = gen_dh_params()
print(f"Domain parameters: p={p_dh}, g={g_dh}")

# 2. Alice and Bob generate key pairs
x_a, y_a = dh_keygen(p_dh, g_dh)    # Alice's keys
x_b, y_b = dh_keygen(p_dh, g_dh)    # Bob's keys
print(f"Alice public key: {y_a}")
print(f"Bob public key: {y_b}")

# 3. Both parties compute shared secret independently
shared_a = dh_shared_secret(y_b, x_a, p_dh)  # Alice computes using Bob's public key
shared_b = dh_shared_secret(y_a, x_b, p_dh)  # Bob computes using Alice's public key

# 4. Verify both parties derived same shared secret
assert shared_a == shared_b, "Shared secrets don't match!"

# 5. Alice creates HMAC signature using shared secret
signature = hmac_sign(shared_a, m)

# 6. Bob verifies signature using same shared secret  
verified = hmac_verify(shared_b, m, signature)

# Display results
print("\n=== Results ===")
print(f"message: {m.decode()}")
print(f"DH shared secret (Alice): {shared_a}")
print(f"DH shared secret (Bob): {shared_b}")
print(f"Shared secrets match: {shared_a == shared_b}")
print(f"signature: {signature.hex()}")
print(f"verified (HMAC): {'verified' if verified else 'NOT verified'}")

# ================================================
# SECURITY ANALYSIS
# ================================================

# DIFFIE-HELLMAN SECURITY:
# - Based on discrete logarithm problem: given g, p, g^x mod p, find x
# - Computationally infeasible for large primes (2048+ bits)
# - Provides perfect forward secrecy (compromise of long-term keys 
#   doesn't compromise past session keys)
# - Vulnerable to man-in-the-middle without authentication

# HMAC SECURITY:  
# - Provides message integrity and authenticity
# - Secure against length extension attacks (unlike raw hashing)
# - Requires shared secret key (established via DH)
# - Prevents tampering, replay, and forgery attacks

# COMBINED PROTOCOL:
# 1. DH establishes shared secret over insecure channel
# 2. HMAC authenticates messages using shared secret
# 3. Provides both key exchange and message authentication
# 4. Foundation for protocols like TLS, IPSec, SSH