# Question 2
# Suppose that XYZ Logistics has decided to use the RSA cryptosystem to secure their
# sensitive communications. However, the security team at XYZ Logistics has discovered
# that one of their employees, Eve, has obtained a partial copy of the RSA private key and
# is attempting to recover the full private key to decrypt the company's communications.
# Eve's attack involves exploiting a vulnerability in the RSA key generation process,
# where the prime factors (p and q) used to generate the modulus (n) are not sufficiently
# large or random.
# Develop a Python script that can demonstrate the attack on the vulnerable RSA
# cryptosystem and discuss the steps to mitigate the attack.


# =========================================
# Demonstration: Weak RSA Vulnerability Attack
# =========================================

from Crypto.Util import number
import math

# -------------------------------
# Utility Functions
# -------------------------------
def generate_weak_rsa_key(bits=32):
    """
    Generate an RSA key pair with small primes (vulnerable scenario).
    WARNING: This is intentionally weak for demonstration.
    """
    p = number.getPrime(bits // 2)   # Small prime p
    q = number.getPrime(bits // 2)   # Small prime q
    n = p * q                        # RSA modulus
    phi = (p - 1) * (q - 1)          # Euler's totient
    e = 65537                         # Common public exponent

    # Compute private key d = e^-1 mod phi
    d = pow(e, -1, phi)
    return {'p': p, 'q': q, 'n': n, 'e': e, 'd': d}

def rsa_encrypt(message, pubkey):
    """
    Encrypt integer message using RSA public key.
    c = m^e mod n
    """
    return pow(message, pubkey['e'], pubkey['n'])

def rsa_decrypt(ciphertext, privkey):
    """
    Decrypt integer ciphertext using RSA private key.
    m = c^d mod n
    """
    return pow(ciphertext, privkey['d'], privkey['n'])

# -------------------------------
# Vulnerable RSA Attack Function
# -------------------------------
def attack_rsa(n, e):
    """
    Attempt to factor RSA modulus n using trial division.
    Works only for small/vulnerable n.
    Returns p, q if successful.
    """
    # Loop from 2 up to sqrt(n)
    for i in range(2, int(math.isqrt(n)) + 1):
        if n % i == 0:
            p = i
            q = n // i
            return p, q
    return None, None  # Failed to factor

# -------------------------------
# Demonstration
# -------------------------------
if __name__ == "__main__":
    # Step 1: Generate a weak RSA key (small primes)
    rsa_key = generate_weak_rsa_key(bits=32)
    print(f"Weak RSA Key Generated:")
    print(f"n = {rsa_key['n']}, e = {rsa_key['e']}, d = {rsa_key['d']}")
    print(f"p = {rsa_key['p']}, q = {rsa_key['q']}\n")

    # Step 2: Encrypt a message
    plaintext = 42
    ciphertext = rsa_encrypt(plaintext, rsa_key)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext}\n")

    # Step 3: Attacker tries to recover private key by factoring n
    print("Attempting to factor n to recover private key...")
    p, q = attack_rsa(rsa_key['n'], rsa_key['e'])
    if p and q:
        print(f"Factors found! p = {p}, q = {q}")
        # Recompute private key
        phi = (p - 1) * (q - 1)
        d_recovered = pow(rsa_key['e'], -1, phi)
        print(f"Recovered private key d = {d_recovered}")

        # Decrypt ciphertext using recovered key
        recovered_plaintext = pow(ciphertext, d_recovered, rsa_key['n'])
        print(f"Recovered Plaintext: {recovered_plaintext}")
    else:
        print("Failed to factor n. Attack unsuccessful.")

# -------------------------------
# Mitigation Strategies
# -------------------------------
"""
1. Use sufficiently large primes (2048-bit or more) for RSA key generation.
2. Ensure primes p and q are generated randomly and independently.
3. Never reuse primes across multiple keys.
4. Avoid small or predictable exponents; use standard e=65537 safely.
5. Protect private key material securely in HSM or encrypted storage.
6. Implement key rotation and revocation policies.
7. Consider alternative algorithms (e.g., ECC) for smaller key sizes with equivalent security.
"""
