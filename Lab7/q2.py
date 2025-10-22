# 2. Utilize the multiplicative homomorphic property of RSA encryption. Implement a
# basic RSA encryption scheme in Python. Encrypt two integers (e.g., 7 and 3) using your
# implementation of the RSA encryption scheme. Print the ciphertexts. Perform a
# multiplication operation on the encrypted integers without decrypting them. Print the
# result of the multiplication in encrypted form. Decrypt the result of the multiplication
# and verify that it matches the product of the original integers.


# E(m1) * E(m2) mod n = E(m1 * m2)

import random
import math

# --- Helper functions ---
def gcd(a, b):
    # Compute Greatest Common Divisor (GCD)
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    # Compute Modular Inverse of 'a' under modulo 'm'
    # Uses the Extended Euclidean Algorithm
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def extended_gcd(a, b):
    # Extended Euclidean Algorithm
    # Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

# --- RSA Key Generation ---
def generate_keypair(p, q):
    # Step 1: Compute n = p * q
    n = p * q

    # Step 2: Compute Euler's Totient Function φ(n) = (p-1)*(q-1)
    phi = (p - 1) * (q - 1)
    
    # Step 3: Choose a public exponent e
    # Commonly used e = 65537 (it's prime and works well)
    e = 65537  
    if gcd(e, phi) != 1:
        # If e and phi(n) are not coprime (rare for small primes), choose another odd number
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    
    # Step 4: Compute private exponent d such that (d * e) ≡ 1 (mod φ(n))
    d = modinv(e, phi)
    
    # Step 5: Return key pairs
    # Public key: (e, n)
    # Private key: (d, n)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

# --- RSA Encryption ---
def encrypt(m, public_key):
    # Encrypt plaintext 'm' using public key (e, n)
    # Formula: c = m^e mod n
    e, n = public_key
    return pow(m, e, n)

# --- RSA Decryption ---
def decrypt(c, private_key):
    # Decrypt ciphertext 'c' using private key (d, n)
    # Formula: m = c^d mod n
    d, n = private_key
    return pow(c, d, n)

# --- Demo Section ---
if __name__ == "__main__":
    # Use small primes (for educational/demo purposes)
    p, q = 61, 53

    # Generate RSA public and private keys
    public_key, private_key = generate_keypair(p, q)
    e, n = public_key

    # Define two integers to encrypt
    m1, m2 = 7, 3
    print(f"Original integers: {m1}, {m2}")

    # Encrypt both integers separately
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    print(f"Encrypted values:\n c1 = {c1}\n c2 = {c2}")

    # --- Homomorphic Multiplication ---
    # RSA is multiplicatively homomorphic:
    # E(m1) * E(m2) mod n = E(m1 * m2)
    c_product = (c1 * c2) % n
    print(f"Encrypted product (ciphertext) = {c_product}")

    # Decrypt the product ciphertext
    decrypted_product = decrypt(c_product, private_key)
    print(f"Decrypted product = {decrypted_product}")
