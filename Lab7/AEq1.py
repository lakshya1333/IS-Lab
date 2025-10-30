# Additional Questions
# Implement similar exercise for other PHE operations (like homomorphic multiplication
# using ElGamal) or explore different functionalities within Paillier.
# 1a: Homomorphic Multiplication (ElGamal Cryptosystem): Implement ElGamal
# encryption and demonstrate homomorphic multiplication on encrypted messages.
# (ElGamal supports multiplication but not homomorphic addition.)
# 1b: Secure Data Sharing (Paillier): Simulate a scenario where two parties share
# 46
# encrypted data and perform calculations on the combined data without decryption.
# 1c: Secure Thresholding (PHE): Explore how PHE can be used for secure multi-party
# computation, where a certain number of parties need to collaborate on a computation
# without revealing their individual data.
# 1d: Performance Analysis (Benchmarking): Compare the performance of different
# PHE schemes (Paillier and ElGamal) for various operations


#!/usr/bin/env python3
"""
phe_demo.py

Demonstrations:
  - ElGamal: encrypt/decrypt and homomorphic multiplication (multiplicative homomorphism).
  - Paillier: encrypt/decrypt and additive homomorphism (secure data sharing).
  - Shamir secret sharing used to simulate thresholding for Paillier private parameter.
  - Simple benchmarking comparing Paillier and ElGamal operations on small inputs.

WARNING: This uses small primes for demonstration only. NOT secure for real use.
"""

import random
import math
import time
from functools import reduce

# -------------------------
# Utilities
# -------------------------
def invmod(a, m):
    """Modular inverse (uses pow for Python >=3.8 where pow supports negative exponent mod)."""
    return pow(a, -1, m)

def is_prime(n):
    """Simple primality test for small integers (deterministic trial division)."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    r = int(n**0.5)
    for i in range(3, r+1, 2):
        if n % i == 0:
            return False
    return True

def next_prime(n):
    """Return the smallest prime > n."""
    candidate = n + 1
    while True:
        if is_prime(candidate):
            return candidate
        candidate += 1

# -------------------------
# ElGamal (multiplicative homomorphism)
# -------------------------
class ElGamal:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        # private key x in [2, p-2]
        self.x = random.randrange(2, p - 1)
        # public key h = g^x mod p
        self.h = pow(g, self.x, p)

    def encrypt(self, m):
        """Encrypt m (must be in Z_p*). Returns (c1, c2)."""
        assert 1 <= m < self.p
        y = random.randrange(2, self.p - 1)
        c1 = pow(self.g, y, self.p)
        c2 = (m * pow(self.h, y, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, ct):
        c1, c2 = ct
        s = pow(c1, self.x, self.p)
        m = (c2 * invmod(s, self.p)) % self.p
        return m

    @staticmethod
    def multiply(ct1, ct2, p):
        """Homomorphic multiplication of two ElGamal ciphertexts."""
        c1 = (ct1[0] * ct2[0]) % p
        c2 = (ct1[1] * ct2[1]) % p
        return (c1, c2)

# -------------------------
# Paillier (additive homomorphism)
# -------------------------
class Paillier:
    def __init__(self, p, q):
        # small primes for demo only
        self.p = p
        self.q = q
        self.n = p * q
        self.n2 = self.n * self.n
        self.g = self.n + 1  # common choice
        # lambda is lcm(p-1, q-1)
        self.lambda_param = math.lcm(p - 1, q - 1)
        # mu = (L(g^lambda mod n^2))^-1 mod n, where L(u) = (u-1)//n
        u = pow(self.g, self.lambda_param, self.n2)
        L = (u - 1) // self.n
        self.mu = invmod(L, self.n)

    def encrypt(self, m):
        """Encrypt integer m (0 <= m < n)."""
        m = m % self.n
        while True:
            r = random.randrange(1, self.n)
            if math.gcd(r, self.n) == 1:
                break
        c = (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2
        return c

    def decrypt(self, c):
        u = pow(c, self.lambda_param, self.n2)
        L = (u - 1) // self.n
        m = (L * self.mu) % self.n
        return m

    def e_add(self, c1, c2):
        """Homomorphic addition: Enc(m1) * Enc(m2) mod n^2 = Enc(m1 + m2)."""
        return (c1 * c2) % self.n2

    def e_mul_const(self, c, k):
        """Homomorphic multiplication by constant: Enc(m)^k = Enc(k*m)."""
        return pow(c, k, self.n2)

# -------------------------
# Shamir Secret Sharing (simple polynomial-based)
# -------------------------
def poly_eval(coeffs, x, p):
    res = 0
    for i, a in enumerate(coeffs):
        res = (res + a * pow(x, i, p)) % p
    return res

def generate_shares(secret, threshold, num_shares, prime):
    """Generate shares (i, share_i) for i=1..num_shares over field prime."""
    coeffs = [secret] + [random.randrange(0, prime) for _ in range(threshold - 1)]
    shares = [(i, poly_eval(coeffs, i, prime)) for i in range(1, num_shares + 1)]
    return shares

def lagrange_interpolate(x, x_s, y_s, p):
    total = 0
    k = len(x_s)
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        num, den = 1, 1
        for j in range(k):
            if i == j:
                continue
            xj = x_s[j]
            num = (num * (x - xj)) % p
            den = (den * (xi - xj)) % p
        inv_den = invmod(den, p)
        total = (total + yi * num * inv_den) % p
    return total

def reconstruct_secret(shares, prime):
    x_s = [s[0] for s in shares]
    y_s = [s[1] for s in shares]
    return lagrange_interpolate(0, x_s, y_s, prime)

# -------------------------
# Demonstrations & Benchmark
# -------------------------
def demo_elgamal():
    print("=== ElGamal Homomorphic Multiplication Demo ===")
    # small prime p and generator g for demo
    p = 467  # small prime
    g = 2
    eg = ElGamal(p, g)

    m1 = 123 % p
    m2 = 17 % p
    ct1 = eg.encrypt(m1)
    ct2 = eg.encrypt(m2)
    ct_prod = ElGamal.multiply(ct1, ct2, p)
    dec_prod = eg.decrypt(ct_prod)

    print(f"m1={m1}, m2={m2}")
    print(f"Decrypted(product) = {dec_prod} (expected {(m1 * m2) % p})\n")
    return eg, (m1, m2), (ct1, ct2, ct_prod)

def demo_paillier_sharing():
    print("=== Paillier Secure Data Sharing Demo ===")
    # small primes for Paillier demo (educational only)
    p = 61
    q = 53
    pa = Paillier(p, q)

    # Two parties
    a = 123
    b = 456
    ca = pa.encrypt(a)
    cb = pa.encrypt(b)
    print(f"Party A plaintext={a}, ciphertext={ca}")
    print(f"Party B plaintext={b}, ciphertext={cb}")

    # Aggregator computes sum on ciphertexts (no decryption)
    csum = pa.e_add(ca, cb)
    dec_sum = pa.decrypt(csum)
    print(f"Decrypted sum = {dec_sum} (expected {(a + b) % pa.n})\n")
    return pa, (a, b), (ca, cb, csum)

def demo_threshold_paillier():
    print("=== Paillier Thresholding Simulation (Shamir on private param) ===")
    p = 61
    q = 53
    pa = Paillier(p, q)

    secret = pa.lambda_param
    # Choose prime field > secret
    prime_field = next_prime(secret + 100)  # ensure prime > secret
    threshold = 3
    num_shares = 5
    shares = generate_shares(secret, threshold, num_shares, prime_field)

    print(f"Secret (lambda) = {secret}")
    print(f"Prime field used for Shamir = {prime_field}")
    print(f"Generated shares (first {num_shares}): {shares}")

    # Reconstruct using threshold shares
    chosen = shares[:threshold]
    rec = reconstruct_secret(chosen, prime_field)
    print(f"Reconstructed secret: {rec} (original {secret})")

    # Demo: aggregator reconstructs secret (only for this simulation) and decrypts aggregate
    a = 10
    b = 20
    ca = pa.encrypt(a)
    cb = pa.encrypt(b)
    csum = pa.e_add(ca, cb)
    dec = pa.decrypt(csum)
    print(f"Decrypted aggregated value (after reconstructing secret): {dec} (expected {(a + b) % pa.n})\n")
    return pa, shares, threshold

def benchmark(pa, eg):
    print("=== Benchmarking Paillier vs ElGamal (simple) ===")
    sizes = [1, 5, 10, 50]
    results = []
    for n in sizes:
        # Paillier: encrypt n numbers, aggregate (homomorphic add), decrypt
        a_vals = [random.randrange(0, pa.n) for _ in range(n)]
        t0 = time.perf_counter()
        cvals = [pa.encrypt(v) for v in a_vals]
        t_enc = time.perf_counter()
        cagg = reduce(lambda x, y: pa.e_add(x, y), cvals)
        t_agg = time.perf_counter()
        dec = pa.decrypt(cagg)
        t_dec = time.perf_counter()

        pa_enc_time = t_enc - t0
        pa_agg_time = t_agg - t_enc
        pa_dec_time = t_dec - t_agg

        # ElGamal: encrypt n numbers, homomorphic multiply, decrypt
        p = eg.p
        m_vals = [random.randrange(1, p) for _ in range(n)]
        t0e = time.perf_counter()
        cvals_e = [eg.encrypt(m) for m in m_vals]
        t_ence = time.perf_counter()
        cprod = reduce(lambda x, y: ElGamal.multiply(x, y, p), cvals_e)
        t_agge = time.perf_counter()
        dec_e = eg.decrypt(cprod)
        t_dece = time.perf_counter()

        eg_enc_time = t_ence - t0e
        eg_agg_time = t_agge - t_ence
        eg_dec_time = t_dece - t_agge

        results.append({
            'n': n,
            'pa_enc': pa_enc_time, 'pa_agg': pa_agg_time, 'pa_dec': pa_dec_time,
            'eg_enc': eg_enc_time, 'eg_agg': eg_agg_time, 'eg_dec': eg_dec_time
        })

        print(f"n={n}: Paillier enc={pa_enc_time:.6f}s agg={pa_agg_time:.6f}s dec={pa_dec_time:.6f}s | "
              f"ElGamal enc={eg_enc_time:.6f}s agg={eg_agg_time:.6f}s dec={eg_dec_time:.6f}s")
    print()
    return results

# -------------------------
# Run demos
# -------------------------
if __name__ == "__main__":
    eg, elg_data, elg_cts = demo_elgamal()
    pa, pa_vals, pa_cts = demo_paillier_sharing()
    pa2, shares, threshold = demo_threshold_paillier()
    bench = benchmark(pa, eg)

    print("=== Summary ===")
    print(" - ElGamal supports multiplicative homomorphism: Enc(m1)*Enc(m2) -> Enc(m1*m2) mod p")
    print(" - Paillier supports additive homomorphism: Enc(m1) * Enc(m2) -> Enc(m1 + m2) mod n")
    print(" - Thresholding demo reconstructs private parameter via Shamir (educational simulation).")
    print("\nCaveat: Use secure key sizes (2048-bit or more) and production-grade libraries for any real deployment.")
