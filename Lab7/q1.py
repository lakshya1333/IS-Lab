# 1. Implement the Paillier encryption scheme in Python. Encrypt two integers (e.g., 15
# and 25) using your implementation of the Paillier encryption scheme. Print the
# ciphertexts. Perform an addition operation on the encrypted integers without decrypting
# them. Print the result of the addition in encrypted form. Decrypt the result of the addition
# and verify that it matches the sum of the original integers.

import random
import math

# --- Helper functions ---
def lcm(a, b):
    # Compute Least Common Multiple (used for lambda)
    return abs(a * b) // math.gcd(a, b)

def modinv(a, m):
    # Compute Modular Inverse of 'a' under modulo 'm' using Extended Euclidean Algorithm
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def extended_gcd(a, b):
    # Extended Euclidean Algorithm
    # Returns (gcd, x, y) where gcd = a*x + b*y
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

# --- Paillier Key Generation ---
def generate_keypair(p, q):
    # Step 1: Compute n = p * q
    n = p * q

    # Step 2: Compute λ = lcm(p-1, q-1)
    lam = lcm(p - 1, q - 1)

    # Step 3: Choose g = n + 1 (simplified choice that works)
    g = n + 1  
    
    # Step 4: Compute μ = (L(g^λ mod n²))^-1 mod n
    x = pow(g, lam, n * n)       # g^λ mod n²
    L = (x - 1) // n             # L(u) = (u - 1) / n
    mu = modinv(L, n)            # μ = L^-1 mod n

    # Public key = (n, g), Private key = (λ, μ)
    public_key = (n, g)
    private_key = (lam, mu)
    return public_key, private_key

# --- Paillier Encryption ---
def encrypt(m, public_key):
    n, g = public_key
    n2 = n * n

    # Choose random r such that gcd(r, n) = 1
    r = random.randint(1, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    # Encryption formula: c = (g^m * r^n) mod n²
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c

# --- Paillier Decryption ---
def decrypt(c, public_key, private_key):
    n, g = public_key
    lam, mu = private_key
    n2 = n * n

    # Step 1: Compute x = c^λ mod n²
    x = pow(c, lam, n2)

    # Step 2: Compute L(x) = (x - 1) // n
    L = (x - 1) // n

    # Step 3: Recover plaintext: m = (L(x) * μ) mod n
    m = (L * mu) % n
    return m

# --- Demo section ---
if __name__ == "__main__":
    # Use small prime numbers for demonstration
    p, q = 47, 59

    # Generate keypair
    public_key, private_key = generate_keypair(p, q)
    n, g = public_key

    # Two integers to encrypt
    m1, m2 = 15, 25
    print(f"Original integers: {m1}, {m2}")

    # Encrypt both integers
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    print(f"Encrypted values:\n c1 = {c1}\n c2 = {c2}")

    # Homomorphic addition:
    # Paillier allows addition of plaintexts by multiplying ciphertexts
    n2 = n * n
    c_sum = (c1 * c2) % n2
    print(f"Encrypted sum (ciphertext) = {c_sum}")

    # Decrypt the sum to verify correctness
    decrypted_sum = decrypt(c_sum, public_key, private_key)
    print(f"Decrypted sum = {decrypted_sum}")
