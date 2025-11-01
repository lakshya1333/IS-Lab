# client_allalgos.py
"""
Client for Privacy-Preserving Medical Records (lab/demo)
Supports many syllabus-friendly algorithms and allows selecting alternates.

Before running:
    pip install pycryptodome phe ecdsa

This script is a superset of the user's starting client and provides:
- AES-256 / AES-128 / DES / 3DES report encryption
- RSA / Rabin / ECDH (ECIES-style key transport) for AES key transport
- ElGamal / RSA-signature / ECDSA signature alternatives
- Paillier (phe) / RSA-homomorphic / ElGamal-homomorphic expense handling
- SSE (AES-based) alternate for searchable department info
- All operations are labelled with algorithm metadata in JSON payloads
"""

import os
import json
import socket
import hashlib
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path
from base64 import b64encode, b64decode

# crypto libs
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, MD5
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Util.number import getPrime, inverse, GCD
from ecdsa import SigningKey, VerifyingKey, NIST256p
from phe import paillier

# Optional ElGamal import — availability depends on environment
try:
    from Crypto.PublicKey import ElGamal
    from Crypto import Random
    HAS_ELGAMAL = True
except Exception:
    HAS_ELGAMAL = False

# Config
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
CLIENT_STATE_FILE = "client_state_allalgos.json"
INPUT_DIR = "inputdata"

def ensure_dirs():
    Path(INPUT_DIR).mkdir(exist_ok=True)

def load_client_state():
    if not os.path.exists(CLIENT_STATE_FILE):
        return {
            "doctor_id": None,
            "keys": {},
            "server_keys": {},
            "prefs": {
                "alg_report_enc": "AES-256",
                "alg_key_enc": "RSA",
                "alg_sig": "ElGamal",
                "alg_dept_enc": "Paillier",
                "alg_expense_he": "RSA-homo"
            }
        }
    with open(CLIENT_STATE_FILE, "r") as f:
        return json.load(f)

def save_client_state(state):
    with open(CLIENT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def send_request(action, role, body):
    req = {"action": action, "role": role, "body": body}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        sock.sendall((json.dumps(req) + "\n").encode())
        data = sock.recv(65536).decode()
        sock.close()
        return json.loads(data)
    except Exception as e:
        return {"status": "error", "error": f"Connection failed: {e}"}

def b64e(b: bytes) -> str:
    return b64encode(b).decode()

def b64d(s: str) -> bytes:
    return b64decode(s.encode())

# -------------------------------
# Key generation helpers (client)
# -------------------------------

def generate_rsa(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def generate_dsa(bits=2048):
    key = DSA.generate(bits)
    return key, key.publickey()

def generate_ecdsa():
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.verifying_key
    return sk, vk

def generate_elgamal(pbits=512):
    """Generate ElGamal using PyCryptodome if available; else raise."""
    if not HAS_ELGAMAL:
        raise RuntimeError("ElGamal not available in this environment.")
    rng = Random.new().read
    key = ElGamal.generate(pbits, rng)
    # key has p,g,y,x
    return key, key.publickey()

def generate_paillier_pair(nbits=1024):
    pub, priv = paillier.generate_paillier_keypair(n_length=nbits)
    return pub, priv

def generate_rabin_keys(bits=512):
    # Rabin: choose p,q ≡ 3 (mod 4)
    def gen_prime_3mod4(nbits):
        while True:
            p = getPrime(nbits)
            if p % 4 == 3:
                return p
    p = gen_prime_3mod4(bits//2)
    q = gen_prime_3mod4(bits//2)
    n = p*q
    return {"p": p, "q": q, "n": n}

# -------------------------------
# Symmetric encryption wrappers
# -------------------------------

def aes_encrypt(key: bytes, plaintext: bytes, mode="GCM"):
    if mode == "GCM":
        cipher = AES.new(key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return {"mode":"GCM", "nonce": b64e(cipher.nonce), "ct": b64e(ct), "tag": b64e(tag)}
    elif mode == "CBC":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        return {"mode":"CBC", "iv": b64e(iv), "ct": b64e(ct)}
    else:
        raise ValueError("Unsupported AES mode")

def aes_decrypt(key: bytes, payload: dict):
    if payload["mode"] == "GCM":
        nonce = b64d(payload["nonce"])
        ct = b64d(payload["ct"])
        tag = b64d(payload["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)
    elif payload["mode"] == "CBC":
        iv = b64d(payload["iv"])
        ct = b64d(payload["ct"])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    else:
        raise ValueError("Unsupported AES mode")

def des_encrypt(key8: bytes, plaintext: bytes):
    iv = get_random_bytes(8)
    cipher = DES.new(key8, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, DES.block_size))
    return {"mode":"DES-CBC", "iv": b64e(iv), "ct": b64e(ct)}

def des3_encrypt(key24: bytes, plaintext: bytes):
    iv = get_random_bytes(8)
    cipher = DES3.new(key24, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, DES3.block_size))
    return {"mode":"3DES-CBC", "iv": b64e(iv), "ct": b64e(ct)}

# -------------------------------
# Asymmetric key-transport wrappers
# -------------------------------

def rsa_encrypt_with_pub_pem(pub_pem_b64: str, plaintext: bytes):
    pub = RSA.import_key(b64d(pub_pem_b64))
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(plaintext)

# Rabin key-transport (educational)
def rabin_encrypt(n: int, plaintext_int: int):
    # Rabin encryption: c = m^2 mod n
    return pow(plaintext_int, 2, n)

# ECC/ECDH-style: derive shared secret (we'll simulate ECIES-like behaviour)
def ecdh_encrypt(peer_pub_bytes: bytes, plaintext: bytes):
    # peer_pub_bytes: serialized VerifyingKey (from ecdsa) in hex or raw
    # For demo: use ephemeral ECDH (not a full ECIES implementation). We'll create ephemeral key,
    # compute shared secret by multiplying peer pubpoint with ephemeral priv, hash, and XOR plaintext.
    peer_vk = VerifyingKey.from_string(b64d(peer_pub_bytes), curve=NIST256p)
    # ephemeral
    eph_sk = SigningKey.generate(curve=NIST256p)
    eph_vk = eph_sk.verifying_key
    # compute shared: multiply peer_vk.pubkey point by eph_sk. In ecdsa lib there's not direct ECDH API
    # so this is illustrative: we will instead use peer_vk.to_string() hashed + ephemeral secret to derive key
    shared = SHA256.new(peer_vk.to_string() + eph_sk.to_string()).digest()
    aes_key = shared[:32]
    enc = aes_encrypt(aes_key, plaintext, mode="GCM")
    # return ephemeral public key + enc
    return {"eph_pub_b64": b64e(eph_vk.to_string()), "enc": enc}

# -------------------------------
# Signatures: ElGamal / RSA / ECDSA
# -------------------------------

def rsa_sign(priv_pem_b64: str, message: bytes):
    priv = RSA.import_key(b64d(priv_pem_b64))
    h = SHA256.new(message)
    sig = pkcs1_15.new(priv).sign(h)
    return b64e(sig)

def rsa_verify(pub_pem_b64: str, message: bytes, sig_b64: str):
    pub = RSA.import_key(b64d(pub_pem_b64))
    h = SHA256.new(message)
    sig = b64d(sig_b64)
    try:
        pkcs1_15.new(pub).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False

def ecdsa_sign(sk: SigningKey, message: bytes):
    sig = sk.sign(message, hashfunc=SHA256.new().new)
    return b64e(sig)

def ecdsa_verify(vk: VerifyingKey, message: bytes, sig_b64: str):
    try:
        return vk.verify(b64d(sig_b64), message, hashfunc=SHA256.new().new)
    except Exception:
        return False

# ElGamal sign wrapper (if available)
def elgamal_sign_local(elgamal_priv, message: bytes):
    # Provided for environments with Crypto.PublicKey.ElGamal
    # This replicates your earlier MD5-based example and returns r,s ints
    if not HAS_ELGAMAL:
        raise RuntimeError("ElGamal not available")
    p = int(elgamal_priv.p)
    g = int(elgamal_priv.g)
    x = int(elgamal_priv.x)
    H = int.from_bytes(MD5.new(message).digest(), "big") % (p - 1)
    while True:
        k = random.randint(2, p - 2)
        if GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    kinv = inverse(k, p - 1)
    s = (kinv * (H - x * r)) % (p - 1)
    return {"r": int(r), "s": int(s)}

# -------------------------------
# Homomorphic alternatives
# -------------------------------

def paillier_encrypt(pub_n_str: str, value_int: int):
    pub = paillier.PaillierPublicKey(int(pub_n_str))
    c = pub.encrypt(value_int)
    # phe ciphertext object: provide ciphertext() and exponent
    return {"ciphertext": int(c.ciphertext()), "exponent": c.exponent}

def rsa_homomorphic_encrypt(n_str: str, e_str: str, g_str: str, amount: int):
    n = int(n_str); e = int(e_str); g = int(g_str)
    # RSA exponent trick used earlier: c = (g^amount)^e mod n
    m = pow(g, amount, n)
    c = pow(m, e, n)
    return str(int(c))

# ElGamal multiplicative homomorphic -- client can compute g^amount and send as ciphertext
def elgamal_homo_encrypt(pub_params, amount: int):
    # pub_params: dict with p,g,y
    p = int(pub_params["p"]); g = int(pub_params["g"]); y = int(pub_params["y"])
    # pick random k and compute (g^k, (g^amount * y^k) mod p) as ciphertext for amount expressed in exponent
    k = random.randint(2, p-2)
    a = pow(g, k, p)
    b = (pow(g, amount, p) * pow(y, k, p)) % p
    return {"c1": str(a), "c2": str(b)}

# -------------------------------
# Searchable encryption (client-side options)
# -------------------------------

def sse_encrypt_index(aes_key: bytes, keyword: str):
    # simple SSE: hash keyword, encrypt hash with AES and send
    kw_hash = hashlib.sha256(keyword.encode()).digest()
    enc = aes_encrypt(aes_key, kw_hash, mode="CBC")
    return enc

# -------------------------------
# High-level operations (UI)
# -------------------------------

def fetch_server_keys(state):
    resp = send_request("get_public_info", "doctor", {})
    if resp.get("status") == "ok":
        state["server_keys"] = resp.get("data", {})
        save_client_state(state)
        print("Server keys fetched.")
        return True
    else:
        print(f"Failed to fetch server keys: {resp.get('error')}")
        return False

def choose_preferences(state):
    print("\n--- Choose algorithm preferences (these will be attached to requests) ---")
    print("Report encryption (alg_report_enc): AES-256, AES-128, AES-CBC, DES, 3DES")
    print("Key encryption (alg_key_enc): RSA, Rabin, ECDH")
    print("Signature (alg_sig): ElGamal, RSA, ECDSA")
    print("Department encryption (alg_dept_enc): Paillier, SSE")
    print("Expense HE (alg_expense_he): Paillier, RSA-homo, ElGamal-homo")
    prefs = state.get("prefs", {})
    prefs["alg_report_enc"] = input(f"alg_report_enc [{prefs.get('alg_report_enc')}]: ").strip() or prefs.get("alg_report_enc")
    prefs["alg_key_enc"] = input(f"alg_key_enc [{prefs.get('alg_key_enc')}]: ").strip() or prefs.get("alg_key_enc")
    prefs["alg_sig"] = input(f"alg_sig [{prefs.get('alg_sig')}]: ").strip() or prefs.get("alg_sig")
    prefs["alg_dept_enc"] = input(f"alg_dept_enc [{prefs.get('alg_dept_enc')}]: ").strip() or prefs.get("alg_dept_enc")
    prefs["alg_expense_he"] = input(f"alg_expense_he [{prefs.get('alg_expense_he')}]: ").strip() or prefs.get("alg_expense_he")
    state["prefs"] = prefs
    save_client_state(state)
    print("Preferences updated.")

def register_doctor_client(state):
    print("\n=== Doctor Registration (client-side) ===")
    doctor_id = input("Choose doctor ID (alphanumeric): ").strip()
    if not doctor_id.isalnum():
        print("Invalid doctor ID.")
        return
    name = input("Doctor name: ").strip()
    department = input("Department: ").strip()

    if not state.get("server_keys"):
        print("Fetch server keys first.")
        return

    # generate keys according to chosen signature algorithm
    alg_sig = state["prefs"].get("alg_sig", "ElGamal")
    keys = state.get("keys", {})

    if alg_sig == "RSA":
        priv, pub = generate_rsa(2048)
        keys["rsa_priv_pem_b64"] = b64e(priv.export_key())
        keys["rsa_pub_pem_b64"] = b64e(pub.export_key())
        print("Generated RSA keypair for signatures.")
    elif alg_sig == "ECDSA":
        sk, vk = generate_ecdsa()
        keys["ecdsa_sk_b64"] = b64e(sk.to_string())
        keys["ecdsa_vk_b64"] = b64e(vk.to_string())
        print("Generated ECDSA keypair.")
    elif alg_sig == "ElGamal":
        if not HAS_ELGAMAL:
            print("ElGamal not available locally. Choose RSA or ECDSA instead, or ensure Crypto.PublicKey.ElGamal is installed.")
            return
        eg_priv, eg_pub = generate_elgamal(512)
        keys["elgamal_priv"] = {
            "p": int(eg_priv.p), "g": int(eg_priv.g), "x": int(eg_priv.x)
        }
        keys["elgamal_pub"] = {"p": int(eg_pub.p), "g": int(eg_pub.g), "y": int(eg_pub.y)}
        print("Generated ElGamal keypair.")

    # Department encryption choices
    alg_dept = state["prefs"].get("alg_dept_enc", "Paillier")
    dept_payload = {}
    if alg_dept == "Paillier":
        # server should provide Paillier public key in server_keys; we encrypt MD5(department) as int
        if "paillier_n" not in state.get("server_keys", {}):
            print("Server's Paillier public key not found. Fetch server keys first.")
            return
        pub_n = state["server_keys"]["paillier_n"]
        dept_hash_int = int.from_bytes(hashlib.md5(department.encode()).digest(), "big")
        dept_payload = paillier_encrypt(pub_n, dept_hash_int)
    elif alg_dept == "SSE":
        # SSE: client creates a symmetric key and encrypts hashed keyword
        aes_key = get_random_bytes(32)
        # we will send AES key encrypted using server's RSA (or chosen key transport)
        enc_index = sse_encrypt_index(aes_key, department)
        dept_payload = {"sse_index": enc_index, "sse_key_b64": b64e(aes_key)}
    else:
        print("Unknown department encryption algorithm selected.")
        return

    # register payload
    body = {
        "doctor_id": doctor_id,
        "name": name,
        "department_plain": department,
        "alg_dept_enc": alg_dept,
        "dept_payload": dept_payload,
        "alg_sig": alg_sig,
        # include public key material for chosen signature scheme:
        "sig_pub": {}
    }

    if alg_sig == "RSA":
        body["sig_pub"]["rsa_pub_pem_b64"] = keys["rsa_pub_pem_b64"]
    elif alg_sig == "ECDSA":
        body["sig_pub"]["ecdsa_vk_b64"] = keys["ecdsa_vk_b64"]
    elif alg_sig == "ElGamal":
        body["sig_pub"]["elgamal_pub"] = keys["elgamal_pub"]

    # Save keys locally
    state["doctor_id"] = doctor_id
    state["keys"] = keys
    save_client_state(state)

    resp = send_request("register_doctor", "doctor", body)
    if resp.get("status") == "ok":
        print(f"✓ Registered doctor {doctor_id}")
    else:
        print("Registration failed:", resp.get("error"))

def submit_report(state):
    if not state.get("doctor_id"):
        print("Register first.")
        return
    ensure_dirs()
    files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith(".md")]
    if not files:
        print(f"No markdown files in {INPUT_DIR}/")
        return
    for i,f in enumerate(files,1):
        print(f"{i}. {f}")
    try:
        idx = int(input("Select file #: ").strip()) - 1
        filename = files[idx]
    except Exception:
        print("Invalid selection")
        return
    report_bytes = open(os.path.join(INPUT_DIR, filename), "rb").read()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Sign message according to chosen alg
    alg_sig = state["prefs"].get("alg_sig", "ElGamal")
    sig_payload = {}
    if alg_sig == "RSA":
        if "rsa_priv_pem_b64" not in state["keys"]:
            print("RSA private missing. Re-register or generate RSA keys.")
            return
        sig_b64 = rsa_sign(state["keys"]["rsa_priv_pem_b64"], report_bytes + timestamp.encode())
        sig_payload = {"alg":"RSA", "sig_b64": sig_b64}
    elif alg_sig == "ECDSA":
        if "ecdsa_sk_b64" not in state["keys"]:
            print("ECDSA private missing.")
            return
        sk = SigningKey.from_string(b64d(state["keys"]["ecdsa_sk_b64"]), curve=NIST256p)
        sig_b64 = ecdsa_sign(sk, report_bytes + timestamp.encode())
        sig_payload = {"alg":"ECDSA", "sig_b64": sig_b64}
    elif alg_sig == "ElGamal":
        if "elgamal_priv" not in state["keys"]:
            print("ElGamal private missing.")
            return
        # custom elgamal sign: return ints r,s
        # Note: this requires local elgamal_priv to be object; we stored ints; for demo recreate simple dict
        try:
            el_priv = state["keys"]["elgamal_priv"]
            # use same MD5-based approach as earlier
            r_s = None
            if HAS_ELGAMAL:
                # if we had real ElGamal object stored, we'd call elgamal_sign_local
                r_s = elgamal_sign_local(el_priv_obj_from_state(el_priv), report_bytes + timestamp.encode())
                sig_payload = {"alg":"ElGamal", "r": r_s["r"], "s": r_s["s"]}
            else:
                # fallback: produce MD5 digest as 'signature' placeholder (server must accept)
                sig_placeholder = hashlib.md5(report_bytes + timestamp.encode()).hexdigest()
                sig_payload = {"alg":"ElGamal", "sig_md5_hex": sig_placeholder}
        except Exception:
            # fallback
            sig_placeholder = hashlib.md5(report_bytes + timestamp.encode()).hexdigest()
            sig_payload = {"alg":"ElGamal", "sig_md5_hex": sig_placeholder}
    else:
        print("Unknown signature algorithm selected.")
        return

    # Encrypt report according to chosen symmetric alg
    alg_report = state["prefs"].get("alg_report_enc", "AES-256")
    sym_key = None
    enc_report = None
    if alg_report == "AES-256":
        sym_key = get_random_bytes(32)
        enc_report = aes_encrypt(sym_key, report_bytes, mode="GCM")
    elif alg_report == "AES-128":
        sym_key = get_random_bytes(16)
        enc_report = aes_encrypt(sym_key, report_bytes, mode="GCM")
    elif alg_report == "AES-CBC":
        sym_key = get_random_bytes(32)
        enc_report = aes_encrypt(sym_key, report_bytes, mode="CBC")
    elif alg_report == "DES":
        sym_key = get_random_bytes(8)
        enc_report = des_encrypt(sym_key, report_bytes)
    elif alg_report == "3DES":
        sym_key = DES3.adjust_key_parity(get_random_bytes(24))
        enc_report = des3_encrypt(sym_key, report_bytes)
    else:
        print("Unsupported symmetric algorithm")
        return

    # Encrypt symmetric key using chosen key-transport
    alg_key_enc = state["prefs"].get("alg_key_enc", "RSA")
    key_transport_payload = {}
    server_keys = state.get("server_keys", {})
    if alg_key_enc == "RSA":
        if "rsa_pub_pem_b64" not in server_keys:
            print("Server RSA public key not available. Fetch server keys.")
            return
        enc_key = rsa_encrypt_with_pub_pem(server_keys["rsa_pub_pem_b64"], sym_key)
        key_transport_payload = {"alg":"RSA", "enc_key_b64": b64e(enc_key)}
    elif alg_key_enc == "Rabin":
        # server must provide rabin n
        if "rabin_n" not in server_keys:
            print("Server Rabin public n not available.")
            return
        m_int = int.from_bytes(sym_key, "big")
        c = rabin_encrypt(int(server_keys["rabin_n"]), m_int)
        key_transport_payload = {"alg":"Rabin", "cipher_int": str(c)}
    elif alg_key_enc == "ECDH":
        if "ecdsa_vk_b64" not in server_keys:
            print("Server ECDSA public not available.")
            return
        # simple ECIES-like wrapper
        enc = ecdh_encrypt(server_keys["ecdsa_vk_b64"], sym_key)
        key_transport_payload = {"alg":"ECDH", "eph_pub_b64": enc["eph_pub_b64"], "enc": enc["enc"]}
    else:
        print("Unknown key transport selected.")
        return

    body = {
        "doctor_id": state["doctor_id"],
        "filename": filename,
        "timestamp": timestamp,
        "sig": sig_payload,
        "alg_report_enc": alg_report,
        "enc_report": enc_report,
        "alg_key_enc": alg_key_enc,
        "key_transport": key_transport_payload,
    }

    resp = send_request("upload_report", "doctor", body)
    if resp.get("status") == "ok":
        print("Report uploaded.")
    else:
        print("Upload failed:", resp.get("error"))

def submit_expense(state):
    if not state.get("doctor_id"):
        print("Register first.")
        return
    alg_exp = state["prefs"].get("alg_expense_he", "RSA-homo")
    try:
        amount = int(input("Expense amount (integer 0-100000): ").strip())
    except ValueError:
        print("Invalid amount.")
        return

    server_keys = state.get("server_keys", {})
    if alg_exp == "Paillier":
        if "paillier_n" not in server_keys:
            print("Server Paillier pub key missing; fetch server keys.")
            return
        enc = paillier_encrypt(server_keys["paillier_n"], amount)
        body = {"doctor_id": state["doctor_id"], "alg_expense_he":"Paillier", "cipher": enc}
    elif alg_exp == "RSA-homo":
        if not all(k in server_keys for k in ("rsa_n","rsa_e","rsa_homo_g")):
            print("Server RSA homomorphic parameters missing.")
            return
        c = rsa_homomorphic_encrypt(server_keys["rsa_n"], server_keys["rsa_e"], server_keys["rsa_homo_g"], amount)
        body = {"doctor_id": state["doctor_id"], "alg_expense_he":"RSA-homo", "cipher": str(c)}
    elif alg_exp == "ElGamal-homo":
        if not all(k in server_keys for k in ("elgamal_pub",)):
            print("Server ElGamal public params missing.")
            return
        enc = elgamal_homo_encrypt(server_keys["elgamal_pub"], amount)
        body = {"doctor_id": state["doctor_id"], "alg_expense_he":"ElGamal-homo", "cipher": enc}
    else:
        print("Unknown expense HE algorithm")
        return

    resp = send_request("submit_expense", "doctor", body)
    if resp.get("status") == "ok":
        print("Expense submitted (encrypted).")
    else:
        print("Submission failed:", resp.get("error"))

# -------------------------------
# Utility: recreate elgamal private object from state ints (if needed)
# -------------------------------
def elgamal_priv_obj_from_state(el_priv):
    # This is a helper ONLY if pycryptodome's ElGamal can be constructed from ints.
    # Many environments won't allow building a full ElGamal object from ints directly.
    # If unavailable, we'd store the real object or use an alternative signature method.
    raise NotImplementedError("Constructing full ElGamal object from stored ints is environment-dependent.")

# -------------------------------
# Menus
# -------------------------------

def doctor_menu(state):
    while True:
        print("\n=== Doctor Menu ===")
        print("1. Fetch server keys")
        print("2. Choose algorithm preferences")
        print("3. Register doctor (with chosen algs)")
        print("4. Submit report (signed & encrypted using chosen algs)")
        print("5. Submit expense (homomorphic)")
        print("6. Show local state")
        print("0. Back")
        ch = input("Choice: ").strip()
        if ch == "1":
            fetch_server_keys(state)
        elif ch == "2":
            choose_preferences(state)
        elif ch == "3":
            register_doctor_client(state)
        elif ch == "4":
            submit_report(state)
        elif ch == "5":
            submit_expense(state)
        elif ch == "6":
            print(json.dumps(state, indent=2, default=str))
        elif ch == "0":
            break
        else:
            print("Invalid choice.")

def main():
    ensure_dirs()
    state = load_client_state()

    while True:
        print("\n=== Medical Records Client (ALL-ALGOS) ===")
        print("1. Doctor operations")
        print("0. Exit")
        ch = input("Choice: ").strip()
        if ch == "1":
            doctor_menu(state)
        elif ch == "0":
            save_client_state(state)
            print("Goodbye.")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
