#!/usr/bin/env python3
"""
server.py - Payment Gateway (Paillier + RSA signing)

Usage:
    python3 server.py

This server:
 - Generates Paillier keypair (public: n, g, n_sq; private: lambda, mu)
 - Generates RSA keypair for signing (n_rsa, e, d)
 - Listens on localhost:65432, accepts JSON messages from sellers
 - For each seller:
    * Receives seller_name and list of encrypted transactions (as decimal strings)
    * Decrypts each encrypted tx, computes homomorphic total (ciphertext multiplication)
    * Decrypts total and verifies sum
    * Builds transaction summary (encrypted amounts, decrypted amounts, totals)
    * Hashes summary (SHA-256) and signs with RSA private key
    * Returns JSON containing the summary and the signature
Notes:
 - Simple socket + JSON protocol, newline delimited messages
"""
#!/usr/bin/env python3
# server.py - Payment Gateway Server

import socket, json, hashlib, random, math
from typing import Tuple

# -------- Utility functions --------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m

def is_prime(n, k=10):
    if n < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0:
            return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p): return p

# -------- Paillier --------
class PaillierPublicKey:
    def __init__(self, n, g):
        self.n, self.g, self.n_sq = n, g, n*n

class PaillierPrivateKey:
    def __init__(self, lam, mu):
        self.lam, self.mu = lam, mu

def paillier_keygen(bits=512):
    p, q = gen_prime(bits//2), gen_prime(bits//2)
    while q == p:
        q = gen_prime(bits//2)
    n = p*q
    g = n + 1
    lam = (p-1)*(q-1)
    n_sq = n*n
    def L(u): return (u - 1)//n
    mu = modinv(L(pow(g, lam, n_sq)), n)
    return PaillierPublicKey(n, g), PaillierPrivateKey(lam, mu)

def paillier_encrypt(pub, m, r=None):
    if r is None:
        r = random.randrange(1, pub.n)
        while math.gcd(r, pub.n) != 1:
            r = random.randrange(1, pub.n)
    return (pow(pub.g, m, pub.n_sq) * pow(r, pub.n, pub.n_sq)) % pub.n_sq

def paillier_decrypt(pub, priv, c):
    def L(u): return (u - 1)//pub.n
    return (L(pow(c, priv.lam, pub.n_sq)) * priv.mu) % pub.n

# -------- RSA --------
def rsa_keygen(bits=1024):
    p, q = gen_prime(bits//2), gen_prime(bits//2)
    n, phi = p*q, (p-1)*(q-1)
    e = 65537
    d = modinv(e, phi)
    return n, e, d

def rsa_sign(n, d, data):
    h = hashlib.sha256(data).digest()
    return pow(int.from_bytes(h, 'big'), d, n)

# -------- Network --------
def send_json(conn, obj):
    conn.sendall(json.dumps(obj).encode() + b'\n')

def recv_json(conn):
    data = b''
    while b'\n' not in data:
        part = conn.recv(4096)
        if not part:
            return None
        data += part
    return json.loads(data.decode().strip())

# -------- Server main --------
HOST, PORT = "127.0.0.1", 65432

def main():
    print("🚀 Payment Gateway starting up...")
    paillier_pub, paillier_priv = paillier_keygen()
    n_rsa, e_rsa, d_rsa = rsa_keygen()
    rsa_keys = (n_rsa, e_rsa, d_rsa)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"✅ Server ready on {HOST}:{PORT}\n")

    while True:
        conn, addr = server.accept()
        print(f"🔗 Connected from {addr}")
        msg = recv_json(conn)

        if msg.get("type") == "hello":
            send_json(conn, {
                "type": "welcome",
                "paillier_public": {"n": str(paillier_pub.n), "g": str(paillier_pub.g)},
                "rsa_public": {"n": str(n_rsa), "e": e_rsa}
            })
            msg = recv_json(conn)

        seller = msg["seller"]
        enc_list = [int(x) for x in msg["encrypted_transactions"]]
        dec_list = [paillier_decrypt(paillier_pub, paillier_priv, c) for c in enc_list]
        total_cipher = 1
        for c in enc_list: total_cipher = (total_cipher * c) % (paillier_pub.n_sq)
        total_plain = paillier_decrypt(paillier_pub, paillier_priv, total_cipher)

        summary = {
            "Seller Name": seller,
            "Decrypted Transactions": dec_list,
            "Encrypted Transactions": [str(x) for x in enc_list],
            "Total Encrypted": str(total_cipher),
            "Total Decrypted": total_plain,
        }

        data = json.dumps(summary, sort_keys=True).encode()
        sig = rsa_sign(n_rsa, d_rsa, data)

        send_json(conn, {
            "summary": summary,
            "signature": str(sig),
            "rsa_public": {"n": str(n_rsa), "e": e_rsa}
        })

        print(f"✅ Processed {seller}")
        conn.close()

if __name__ == "__main__":
    main()
