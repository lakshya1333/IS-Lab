#!/usr/bin/env python3
"""
client.py

Doctor and Auditor interactive client.

Doctor capabilities:
 - generate ElGamal keypair (signing)
 - register (encrypt department bloom bits under auditor Paillier pub and send)
 - submit AES-encrypted report; AES key encrypted under server ElGamal pub; sign report with ElGamal signature
 - log expense: encode amount via g^amount mod p and encrypt under auditor ElGamal pub

Auditor capabilities:
 - generate Paillier keypair (private kept by auditor)
 - upload auditor public keys to server
 - search departments by keyword: server returns per-doctor Paillier ciphertext (enc of dot product), auditor decrypts to see matches
 - get encrypted expense aggregates (ElGamal multiplicative aggregates) and decrypt sums via discrete-log (works for small totals)
 - verify report signature and timestamp (ElGamal signature verify)
"""
import os
import json
import socket
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from Crypto.PublicKey import ElGamal
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import GCD, inverse
from phe import paillier

# Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
CLIENT_STATE_FILE = "client_state.json"
INPUT_DIR = "inputdata"


def ensure_dirs():
    Path(INPUT_DIR).mkdir(exist_ok=True)


def load_client_state():
    if not os.path.exists(CLIENT_STATE_FILE):
        return {"doctor_id": None, "elgamal": {}, "server_keys": {}}
    with open(CLIENT_STATE_FILE, "r") as f:
        return json.load(f)


def save_client_state(state):
    with open(CLIENT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def send_request(action, role, body):
    """Send JSON request to server and receive response."""
    req = {"action": action, "role": role, "body": body}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        sock.sendall((json.dumps(req) + "\n").encode())
        data = sock.recv(4096).decode()
        sock.close()
        return json.loads(data)
    except Exception as e:
        return {"status": "error", "error": f"Connection failed: {e}"}


def b64e(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode())


def fetch_server_keys(state):
    """Get server's public keys."""
    resp = send_request("get_public_info", "doctor", {})
    if resp.get("status") == "ok":
        state["server_keys"] = resp.get("data", {})
        save_client_state(state)
        print("Server keys fetched.")
        return True
    else:
        print(f"Failed to fetch server keys: {resp.get('error')}")
        return False


def register_doctor_client(state):
    """Register a new doctor with the server."""
    print("\n=== Doctor Registration ===")
    doctor_id = input("Choose doctor ID (alphanumeric): ").strip()
    if not doctor_id.isalnum():
        print("Invalid doctor ID.")
        return

    name = input("Doctor name: ").strip()
    department = input("Department: ").strip()

    if not state["server_keys"]:
        print("Fetch server keys first.")
        return

    # Generate ElGamal keypair
    print("Generating ElGamal keypair...")
    eg_key = ElGamal.generate(512, get_random_bytes)
    p = int(eg_key.p)
    g = int(eg_key.g)
    y = int(eg_key.y)
    x = int(eg_key.x)

    state["doctor_id"] = doctor_id
    state["elgamal"] = {"p": p, "g": g, "y": y, "x": x}

    # Encrypt department using Paillier
    paillier_n = int(state["server_keys"]["paillier_n"])
    paillier_pub = paillier.PaillierPublicKey(paillier_n)

    dept_hash = int.from_bytes(hashlib.sha256(department.encode()).digest(), "big")
    dept_enc = paillier_pub.encrypt(dept_hash)

    # Prepare request
    body = {
        "doctor_id": doctor_id,
        "department_plain": department,
        "dept_enc": {
            "ciphertext": int(dept_enc.ciphertext()),
            "exponent": dept_enc.exponent,
        },
        "elgamal_pub": {"p": p, "g": g, "y": y},
    }

    resp = send_request("register_doctor", "doctor", body)
    if resp.get("status") == "ok":
        save_client_state(state)
        print(f"✓ Doctor '{doctor_id}' registered successfully.")
        print(f"  Name: {name}, Department: {department}")
    else:
        print(f"✗ Registration failed: {resp.get('error')}")


def elgamal_sign(eg_private, msg_bytes):
    """Sign message with ElGamal using SHA256."""
    p = int(eg_private["p"])
    g = int(eg_private["g"])
    x = int(eg_private["x"])

    H = int.from_bytes(SHA256.new(msg_bytes).digest(), "big") % (p - 1)
    while True:
        k = random.randint(2, p - 2)
        if GCD(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    kinv = inverse(k, p - 1)
    s = (kinv * (H - x * r)) % (p - 1)
    return int(r), int(s)


def elgamal_encrypt(pub, plaintext_bytes):
    """Encrypt AES key using ElGamal."""
    p, g, y = pub["p"], pub["g"], pub["y"]
    m = int.from_bytes(plaintext_bytes, "big")
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return c1, c2


def submit_report(state):
    """Submit a medical report (encrypted with AES, key encrypted with ElGamal)."""
    if not state["doctor_id"]:
        print("Register as doctor first.")
        return

    ensure_dirs()
    files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith(".md")]
    if not files:
        print("Place markdown files in inputdata/")
        return

    print("\nAvailable files:")
    for i, f in enumerate(files, 1):
        print(f"  {i}. {f}")

    try:
        idx = int(input("Select file #: ").strip()) - 1
        filename = files[idx]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    filepath = os.path.join(INPUT_DIR, filename)
    with open(filepath, "rb") as f:
        report_bytes = f.read()

    timestamp = datetime.now(timezone.utc).isoformat()
    sha_hex = hashlib.sha256(report_bytes).hexdigest()

    # Sign report
    msg_to_sign = report_bytes + timestamp.encode()
    r, s = elgamal_sign(state["elgamal"], msg_to_sign)

    # Encrypt report with AES-256-EAX
    aes_key = get_random_bytes(32)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(report_bytes)

    # Encrypt AES key using server’s ElGamal public key
    elgamal_pub = state["server_keys"]["elgamal_pub"]
    c1, c2 = elgamal_encrypt(elgamal_pub, aes_key)

    # Prepare request
    body = {
        "doctor_id": state["doctor_id"],
        "filename": filename,
        "timestamp": timestamp,
        "sha256_hex": sha_hex,
        "sig": {"r": r, "s": s},
        "aes": {
            "key_elgamal": {"c1": c1, "c2": c2},
            "nonce_b64": b64e(cipher.nonce),
            "tag_b64": b64e(tag),
            "ct_b64": b64e(ciphertext),
        },
    }

    resp = send_request("upload_report", "doctor", body)
    if resp.get("status") == "ok":
        print(f"✓ Report '{filename}' uploaded successfully.")
        print(f"  SHA256: {sha_hex}")
        print(f"  Timestamp: {timestamp}")
    else:
        print(f"✗ Upload failed: {resp.get('error')}")


def doctor_menu(state):
    """Doctor submenu."""
    while True:
        print("\n=== Doctor Menu ===")
        print("1. Register with server")
        print("2. Fetch server keys")
        print("3. Submit report (encrypted)")
        print("4. Exit")

        ch = input("Choice: ").strip()
        if ch == "1":
            register_doctor_client(state)
        elif ch == "2":
            fetch_server_keys(state)
        elif ch == "3":
            submit_report(state)
        elif ch == "4":
            break
        else:
            print("Invalid choice.")


def main():
    ensure_dirs()
    state = load_client_state()

    while True:
        print("\n=== Medical Records Client ===")
        print("1. Doctor operations")
        print("0. Exit")

        ch = input("Choice: ").strip()
        if ch == "1":
            doctor_menu(state)
        elif ch == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
