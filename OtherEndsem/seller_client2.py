#!/usr/bin/env python3
"""
client.py - Seller client

Usage:
    python3 client.py SellerName

Example:
    python3 client.py SellerA

The seller:
 - Connects to the gateway at localhost:65432
 - Sends "hello" to get Paillier public params and RSA public key
 - Encrypts a list of transaction amounts using Paillier pubkey
 - Sends seller_name and encrypted_transactions to gateway
 - Receives signed summary and verifies RSA signature (SHA-256)
 - Prints a readable transaction summary and signature verification result
"""

#!/usr/bin/env python3
# client.py - Interactive Seller

import socket, json, sys, random, math, hashlib

def paillier_encrypt(n, g, m):
    n_sq = n * n
    r = random.randrange(1, n)
    while math.gcd(r, n) != 1:
        r = random.randrange(1, n)
    return (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq

def rsa_verify(n, e, data, sig):
    h = hashlib.sha256(data).digest()
    return pow(sig, e, n) == int.from_bytes(h, 'big') % n

def send_json(sock, obj): sock.sendall(json.dumps(obj).encode() + b'\n')
def recv_json(sock):
    data = b''
    while b'\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode().strip())

HOST, PORT = "127.0.0.1", 65432

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 client.py SellerName")
        sys.exit(1)

    seller = sys.argv[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    send_json(sock, {"type": "hello", "seller": seller})
    welcome = recv_json(sock)
    n = int(welcome["paillier_public"]["n"])
    g = int(welcome["paillier_public"]["g"])
    rsa_pub = welcome["rsa_public"]

    print(f"\n💳 Connected as {seller}")
    print("Enter your transaction amounts below (type 'done' when finished):")

    txs = []
    while True:
        val = input("Amount ₹ (or 'done'): ").strip()
        if val.lower() == "done":
            break
        if val.isdigit():
            txs.append(int(val))
        else:
            print("❌ Invalid input — enter a number or 'done'")

    if not txs:
        print("⚠️ No transactions entered. Exiting.")
        return

    enc = [str(paillier_encrypt(n, g, m)) for m in txs]

    send_json(sock, {"seller": seller, "encrypted_transactions": enc})
    resp = recv_json(sock)
    sock.close()

    summary = resp["summary"]
    sig = int(resp["signature"])
    rsa_n, rsa_e = int(rsa_pub["n"]), int(rsa_pub["e"])

    data = json.dumps(summary, sort_keys=True).encode()
    verified = rsa_verify(rsa_n, rsa_e, data, sig)

    print("\n🧾 Transaction Summary")
    print("=" * 60)
    print(f"Seller Name: {summary['Seller Name']}")
    print("Individual Transaction Amounts:", summary["Decrypted Transactions"])
    print("\nEncrypted Transaction Amounts:")
    for i, val in enumerate(summary["Encrypted Transactions"], 1):
        print(f"  Tx{i}: {val[:50]}...")

    print(f"\nTotal Encrypted (truncated): {summary['Total Encrypted'][:60]}...")
    print(f"Total Decrypted Amount: ₹{summary['Total Decrypted']}")
    print(f"Digital Signature Verification: {'✅ Valid' if verified else '❌ Invalid'}")
    print("=" * 60)

if __name__ == "__main__":
    main()
