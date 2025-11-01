# server_allalgos.py
"""
Server updated to interoperate with client_allalgos.py produced earlier.

Features:
- Exposes RSA / Paillier / Rabin (public) / ECDSA (verifying key) / RSA-homomorphic base g
- Accepts alg_* fields and branches:
    alg_report_enc: AES-256 / AES-128 / AES-CBC / DES / 3DES
    alg_key_enc: RSA / Rabin / ECDH  (RSA fully supported)
    alg_sig: ElGamal / RSA / ECDSA
    alg_dept_enc: Paillier / SSE
    alg_expense_he: Paillier / RSA-homo / ElGamal-homo (store)
- Auditor functions for keyword search (Paillier or SSE), sum expenses (Paillier or RSA-homo), verify reports (RSA/ECDSA/ElGamal)
"""

import os
import json
import threading
import socketserver
import base64
import time
import random
from datetime import datetime, timezone
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.number import GCD, getPrime
from Crypto.Hash import SHA256, MD5
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

from phe import paillier
from ecdsa import SigningKey, VerifyingKey, NIST256p

# Storage config
DATA_DIR = "server_data"
DOCTORS_FILE = os.path.join(DATA_DIR, "doctors.json")
EXPENSES_FILE = os.path.join(DATA_DIR, "expenses.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports.json")
CONF_FILE = os.path.join(DATA_DIR, "config.json")
RSA_PRIV_FILE = os.path.join(DATA_DIR, "server_rsa_priv.pem")
RSA_PUB_FILE = os.path.join(DATA_DIR, "server_rsa_pub.pem")
ECDSA_PRIV_FILE = os.path.join(DATA_DIR, "server_ecdsa_priv.pem")
ECDSA_PUB_FILE = os.path.join(DATA_DIR, "server_ecdsa_pub.pem")

PORT = 5000
lock = threading.Lock()

# ---------------------------
# Helpers for base64
# ---------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

# ---------------------------
# File/JSON utilities
# ---------------------------
def ensure_dirs():
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

def read_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)

def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

# ---------------------------
# Key generation / loading
# ---------------------------
def load_or_create_rsa():
    if not os.path.exists(RSA_PRIV_FILE):
        key = RSA.generate(2048)
        with open(RSA_PRIV_FILE, "wb") as f:
            f.write(key.export_key())
        with open(RSA_PUB_FILE, "wb") as f:
            f.write(key.public_key().export_key())
    with open(RSA_PRIV_FILE, "rb") as f:
        priv = RSA.import_key(f.read())
    with open(RSA_PUB_FILE, "rb") as f:
        pub = RSA.import_key(f.read())
    return priv, pub

def load_or_create_ecdsa():
    # store raw private/verifying key strings (not PEM) using ecdsa lib
    if not os.path.exists(ECDSA_PRIV_FILE) or not os.path.exists(ECDSA_PUB_FILE):
        sk = SigningKey.generate(curve=NIST256p)
        vk = sk.verifying_key
        with open(ECDSA_PRIV_FILE, "wb") as f:
            f.write(sk.to_string())
        with open(ECDSA_PUB_FILE, "wb") as f:
            f.write(vk.to_string())
    with open(ECDSA_PRIV_FILE, "rb") as f:
        sk_bytes = f.read()
    with open(ECDSA_PUB_FILE, "rb") as f:
        vk_bytes = f.read()
    sk = SigningKey.from_string(sk_bytes, curve=NIST256p)
    vk = VerifyingKey.from_string(vk_bytes, curve=NIST256p)
    return sk, vk

def load_or_create_paillier():
    conf = read_json(CONF_FILE, {})
    if "paillier" not in conf:
        pubkey, privkey = paillier.generate_paillier_keypair(n_length=1024)
        conf["paillier"] = {"n": str(pubkey.n), "p": str(privkey.p), "q": str(privkey.q)}
        write_json(CONF_FILE, conf)
    conf = read_json(CONF_FILE, {})
    n = int(conf["paillier"]["n"])
    p = int(conf["paillier"]["p"])
    q = int(conf["paillier"]["q"])
    pub = paillier.PaillierPublicKey(n)
    priv = paillier.PaillierPrivateKey(pub, p, q)
    return pub, priv

def load_or_create_rabin():
    # Rabin: choose p,q ≡ 3 (mod 4). Store n publicly.
    conf = read_json(CONF_FILE, {})
    if "rabin" not in conf:
        # generate p,q each 512 bits
        def gen_3mod4(bits):
            while True:
                x = getPrime(bits)
                if x % 4 == 3:
                    return x
        p = gen_3mod4(512)
        q = gen_3mod4(512)
        conf["rabin"] = {"p": str(p), "q": str(q), "n": str(p*q)}
        write_json(CONF_FILE, conf)
    conf = read_json(CONF_FILE, {})
    p = int(conf["rabin"]["p"]); q = int(conf["rabin"]["q"]); n = int(conf["rabin"]["n"])
    return {"p": p, "q": q, "n": n}

def load_or_create_rsa_homog_base(rsa_pub):
    conf = read_json(CONF_FILE, {})
    if "rsa_homomorphic" not in conf:
        # pick base g coprime to n
        n = rsa_pub.n
        while True:
            g = random.randrange(2, n-1)
            if GCD(g, n) == 1:
                break
        conf["rsa_homomorphic"] = {"g": str(g)}
        write_json(CONF_FILE, conf)
    conf = read_json(CONF_FILE, {})
    return int(conf["rsa_homomorphic"]["g"])

# ---------------------------
# Init storage & keys
# ---------------------------
ensure_dirs()
RSA_PRIV, RSA_PUB = load_or_create_rsa()
ECDSA_SK, ECDSA_VK = load_or_create_ecdsa()
PAI_PUB, PAI_PRIV = load_or_create_paillier()
RABIN = load_or_create_rabin()
RSA_HOMO_G = load_or_create_rsa_homog_base(RSA_PUB)

# ensure JSON files exist
if not os.path.exists(DOCTORS_FILE):
    write_json(DOCTORS_FILE, {})
if not os.path.exists(EXPENSES_FILE):
    write_json(EXPENSES_FILE, [])
if not os.path.exists(REPORTS_FILE):
    write_json(REPORTS_FILE, [])

# ---------------------------
# Public info for clients
# ---------------------------
def get_public_info():
    return {
        "rsa_pub_pem_b64": b64e(RSA_PUB.export_key()),
        "rsa_n": str(RSA_PUB.n),
        "rsa_e": str(RSA_PUB.e),
        "paillier_n": str(PAI_PUB.n),
        "rabin_n": str(RABIN["n"]),
        "ecdsa_vk_b64": b64e(ECDSA_VK.to_string()),
        "rsa_homo_g": str(RSA_HOMO_G),
    }

# ---------------------------
# Department (register) handling
# ---------------------------
def handle_register_doctor(body):
    """
    Accepts flexible dept payloads depending on alg_dept_enc:
      - Paillier: dept_payload = {"ciphertext":int, "exponent":int}
      - SSE: dept_payload = {"sse_index": {...}, "sse_key_b64": "<b64>"}
    Also accepts signature public key material in body["sig_pub"]
    """
    doc_id = str(body.get("doctor_id","")).strip()
    name = str(body.get("name","")).strip()
    alg_dept = body.get("alg_dept_enc", "Paillier")
    dept_plain = str(body.get("department_plain","")).strip()
    dept_payload = body.get("dept_payload", {})
    sig_pub = body.get("sig_pub", {})

    if not doc_id or not doc_id.isalnum():
        return {"status":"error","error":"invalid doctor_id"}
    if not name:
        return {"status":"error","error":"invalid name"}

    # validate dept payload per algorithm
    if alg_dept == "Paillier":
        if not dept_payload or "ciphertext" not in dept_payload or "exponent" not in dept_payload:
            return {"status":"error","error":"missing paillier payload"}
        # store as strings
        dept_enc = {"ciphertext": str(int(dept_payload["ciphertext"])), "exponent": int(dept_payload["exponent"]), "type":"Paillier"}
    elif alg_dept == "SSE":
        # expect sse_index and sse_key_b64
        if not dept_payload or "sse_index" not in dept_payload or "sse_key_b64" not in dept_payload:
            return {"status":"error","error":"missing SSE payload"}
        dept_enc = {"sse_index": dept_payload["sse_index"], "sse_key_b64": str(dept_payload["sse_key_b64"]), "type":"SSE"}
    else:
        return {"status":"error","error":"unsupported alg_dept_enc"}

    # persistent store
    with lock:
        doctors = read_json(DOCTORS_FILE, {})
        doctors[doc_id] = {
            "name": name,
            "department_plain": dept_plain,
            "dept_enc": dept_enc,
            "sig_pub": sig_pub,   # e.g. {"rsa_pub_pem_b64":..., "ecdsa_vk_b64":..., "elgamal_pub": {...}}
            "registered_at": datetime.utcnow().isoformat()
        }
        write_json(DOCTORS_FILE, doctors)
    print(f"[server] registered doctor {doc_id} alg_dept_enc={alg_dept}")
    return {"status":"ok"}

# ---------------------------
# Helpers: symmetric decrypt wrappers
# ---------------------------
def aes_decrypt_payload(sym_key: bytes, enc_payload: dict):
    mode = enc_payload.get("mode", "GCM")
    if mode == "GCM":
        nonce = b64d(enc_payload["nonce"])
        ct = b64d(enc_payload["ct"])
        tag = b64d(enc_payload["tag"])
        cipher = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(ct, tag)
        return plain
    elif mode == "CBC":
        iv = b64d(enc_payload["iv"])
        ct = b64d(enc_payload["ct"])
        cipher = AES.new(sym_key, AES.MODE_CBC, iv)
        plain = unpad(cipher.decrypt(ct), AES.block_size)
        return plain
    else:
        raise ValueError("Unsupported AES mode")

def des_decrypt_payload(key8: bytes, enc_payload: dict):
    iv = b64d(enc_payload["iv"])
    ct = b64d(enc_payload["ct"])
    cipher = DES.new(key8, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size)

def des3_decrypt_payload(key24: bytes, enc_payload: dict):
    iv = b64d(enc_payload["iv"])
    ct = b64d(enc_payload["ct"])
    cipher = DES3.new(key24, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES3.block_size)

# ---------------------------
# Rabin decryption helper (educational)
# ---------------------------
def rabin_decrypt(priv, ciphertext_int):
    """
    Rabin decryption returns up to 4 roots. Without redundancy we cannot
    be sure which root is original message. This function returns the
    four possible roots (as bytes) and the caller must pick the correct one.
    """
    p = priv["p"]; q = priv["q"]; n = priv["n"]
    c = ciphertext_int % n
    # compute mp, mq as sqrt(c) mod p and q using exponent (p+1)/4 since p ≡ 3 mod 4
    mp = pow(c, (p+1)//4, p)
    mq = pow(c, (q+1)//4, q)
    # use CRT to combine mp,mq into 4 roots
    # find coefficients yp, yq such that yp*p + yq*q = 1
    def egcd(a,b):
        if b==0: return (1,0,a)
        x,y,g = egcd(b, a%b)
        return (y, x - (a//b)*y, g)
    yp, yq, _ = egcd(p, q)
    yp = yp % q
    yq = yq % p
    roots = []
    for s1 in [mp, (-mp)%p]:
        for s2 in [mq, (-mq)%q]:
            # CRT recombination
            r = (s1 * q * yq + s2 * p * yp) % n
            roots.append(r)
    # return list of candidate byte-strings
    return [int.to_bytes(r, (n.bit_length()+7)//8, "big") for r in roots]

# ---------------------------
# Handle report upload (flexible)
# ---------------------------
def handle_upload_report(body):
    """
    body includes:
      - doctor_id, filename, timestamp
      - sig: signature payload (alg dependent)
      - alg_report_enc, enc_report (payload)
      - alg_key_enc, key_transport (payload)
    Server tries to:
      1) obtain symmetric key using key_transport (supports RSA)
      2) decrypt report using chosen sym alg payload (AES/DES/3DES)
      3) verify signature using stored public key (RSA/ECDSA/ElGamal)
      4) store decrypted file and metadata (even if decryption not possible)
    """
    doc_id = str(body.get("doctor_id","")).strip()
    filename = os.path.basename(body.get("filename","")).strip()
    timestamp = body.get("timestamp","")
    sig = body.get("sig", {})
    alg_report = body.get("alg_report_enc", "AES-256")
    enc_report = body.get("enc_report", {})
    alg_key_enc = body.get("alg_key_enc", "RSA")
    key_transport = body.get("key_transport", {})

    if not doc_id or not filename:
        return {"status":"error","error":"missing doc_id/filename"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status":"error","error":"unknown doctor"}

    sym_key = None
    # Key-transport handling: RSA supported (OAEP)
    if alg_key_enc == "RSA":
        try:
            enc_key_b64 = key_transport.get("enc_key_b64")
            if not enc_key_b64:
                return {"status":"error","error":"missing enc_key_b64 for RSA key transport"}
            rsa_cipher = PKCS1_OAEP.new(RSA_PRIV)
            sym_key = rsa_cipher.decrypt(b64d(enc_key_b64))
        except Exception as e:
            return {"status":"error","error": f"RSA key transport decryption failed: {e}"}
    elif alg_key_enc == "Rabin":
        # store the rabin ciphertext; server can attempt decrypt only if client included redundancy
        # attempt to decode if key_transport contains 'cipher_int' and client included redundancy in plaintext
        try:
            c_int = int(key_transport.get("cipher_int"))
            # try to get candidate roots
            candidates = rabin_decrypt(RABIN, c_int)
            # try to pick candidate with a prefix "KEY:" (convention) else fail
            chosen = None
            for cand in candidates:
                if cand.startswith(b"KEY:"):
                    chosen = cand[4:]
                    break
            if chosen:
                sym_key = chosen
            else:
                # cannot pick root unambiguously
                return {"status":"error","error":"Rabin decryption ambiguous: no redundancy prefix found"}
        except Exception as e:
            return {"status":"error","error": f"Rabin handling failed: {e}"}
    elif alg_key_enc == "ECDH":
        # Client's illustrative EC method is not compatible; we can't derive same shared secret.
        return {"status":"error","error":"ECDH key transport (client-side variant) not supported by server. Use RSA key transport."}
    else:
        return {"status":"error","error":"unknown key transport algorithm"}

    # Decrypt report bytes using sym_key and alg_report
    report_bytes = None
    try:
        if alg_report in ("AES-256","AES-128","AES-CBC"):
            # enc_report must contain mode and fields produced by client's aes_encrypt
            # derive proper key length from alg_report
            if alg_report == "AES-128":
                if len(sym_key) < 16:
                    return {"status":"error","error":"sym_key too short for AES-128"}
                k = sym_key[:16]
            else:
                k = sym_key
            report_bytes = aes_decrypt_payload(k, enc_report)
        elif alg_report == "DES":
            # DES key is 8 bytes
            report_bytes = des_decrypt_payload(sym_key[:8], enc_report)
        elif alg_report == "3DES":
            report_bytes = des3_decrypt_payload(sym_key[:24], enc_report)
        else:
            return {"status":"error","error":"unsupported report symmetric algorithm"}
    except Exception as e:
        # Decryption failed: store payload for auditing / debugging
        print(f"[server] symmetric decrypt failed: {e}")
        # still store encrypted payload but note error
        report_bytes = None

    # If we got plaintext, verify md5 if provided
    md5_hex = body.get("md5_hex", "")
    if report_bytes is not None and md5_hex:
        import hashlib
        if hashlib.md5(report_bytes).hexdigest() != md5_hex:
            print("[server] WARNING: md5 mismatch for uploaded report")

    # Signature verification (best-effort)
    sig_ok = False
    alg_sig = sig.get("alg", None)  # client may have included alg inside sig payload; otherwise rely on doctor's registered sig_pub
    registered_sig_pub = doctors[doc_id].get("sig_pub", {})

    # try to determine signature algorithm and verify accordingly
    # 1) if sig has 'sig_b64' and registered_sig_pub has rsa pub -> RSA verify
    if "sig_b64" in sig and "rsa_pub_pem_b64" in registered_sig_pub:
        try:
            pub = RSA.import_key(b64d(registered_sig_pub["rsa_pub_pem_b64"]))
            h = SHA256.new((report_bytes or b"") + timestamp.encode())
            pkcs1_15.new(pub).verify(h, b64d(sig["sig_b64"]))
            sig_ok = True
        except Exception:
            sig_ok = False
    # 2) ECDSA
    elif "sig_b64" in sig and "ecdsa_vk_b64" in registered_sig_pub:
        try:
            vk = VerifyingKey.from_string(b64d(registered_sig_pub["ecdsa_vk_b64"]), curve=NIST256p)
            vk.verify(b64d(sig["sig_b64"]), (report_bytes or b"") + timestamp.encode(), hashfunc=SHA256.new().new)
            sig_ok = True
        except Exception:
            sig_ok = False
    # 3) ElGamal style (client used MD5-based H and r,s ints). Check for elgamal_pub in registered_sig_pub.
    elif "r" in sig and "s" in sig and "elgamal_pub" in registered_sig_pub:
        try:
            el = registered_sig_pub["elgamal_pub"]
            p = int(el["p"]); g = int(el["g"]); y = int(el["y"])
            r = int(sig["r"]); s = int(sig["s"])
            # H as per client: MD5(report || timestamp) mod (p-1)
            H = int.from_bytes(MD5.new((report_bytes or b"") + timestamp.encode()).digest(), "big") % (p-1)
            # verify: g^H == y^r * r^s (mod p)
            left = pow(g, H, p)
            right = (pow(y, r, p) * pow(r, s, p)) % p
            sig_ok = (left == right)
        except Exception:
            sig_ok = False
    else:
        # unknown or unsupported signature format
        sig_ok = False

    # Save file if we have plaintext, otherwise store encrypted payload
    outdir = os.path.join(DATA_DIR, "reports")
    os.makedirs(outdir, exist_ok=True)
    timestamp_suffix = int(time.time())
    saved_path = os.path.join(outdir, f"{doc_id}_{timestamp_suffix}_{filename}")
    if report_bytes is not None:
        with open(saved_path, "wb") as f:
            f.write(report_bytes)
    else:
        # store encrypted blob as JSON-serializable file
        saved_path = os.path.join(outdir, f"{doc_id}_{timestamp_suffix}_{filename}.enc.json")
        with open(saved_path, "w") as f:
            json.dump({"enc_report": enc_report, "key_transport": key_transport, "alg_report_enc": alg_report, "alg_key_enc": alg_key_enc}, f)

    rec = {
        "doctor_id": doc_id,
        "filename": filename,
        "saved_path": saved_path,
        "timestamp": timestamp,
        "md5_hex": md5_hex,
        "sig": sig if sig else {},
        "sig_ok": bool(sig_ok),
        "alg_report_enc": alg_report,
        "alg_key_enc": alg_key_enc,
    }
    with lock:
        recs = read_json(REPORTS_FILE, [])
        recs.append(rec)
        write_json(REPORTS_FILE, recs)
    print(f"[server] stored report {saved_path} sig_ok={sig_ok}")
    return {"status":"ok", "sig_ok": sig_ok}

# ---------------------------
# Expense handling
# ---------------------------
def handle_submit_expense(body):
    """
    body: {doctor_id, alg_expense_he, cipher}
    For alg:
      - Paillier: cipher is {"ciphertext": int, "exponent": int}
      - RSA-homo: cipher is string int
      - ElGamal-homo: cipher is dict with c1,c2
    """
    doc_id = str(body.get("doctor_id","")).strip()
    alg = body.get("alg_expense_he", "RSA-homo")
    cipher = body.get("cipher")
    if not doc_id or not doc_id.isalnum():
        return {"status":"error","error":"invalid doctor_id"}
    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status":"error","error":"unknown doctor"}

    rec = {"doctor_id": doc_id, "alg": alg, "cipher": cipher, "ts": datetime.utcnow().isoformat()}
    with lock:
        exps = read_json(EXPENSES_FILE, [])
        exps.append(rec)
        write_json(EXPENSES_FILE, exps)
    print(f"[server] stored expense for {doc_id} alg={alg}")
    return {"status":"ok"}

# ---------------------------
# Request Handler
# ---------------------------
class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            data = self.rfile.readline()
            if not data:
                return
            req = json.loads(data.decode())
            action = req.get("action")
            role = req.get("role", "")
            body = req.get("body", {})
            if action == "get_public_info":
                resp = {"status":"ok","data": get_public_info()}
            elif action == "register_doctor":
                if role != "doctor":
                    resp = {"status":"error","error":"unauthorized"}
                else:
                    resp = handle_register_doctor(body)
            elif action == "upload_report":
                if role != "doctor":
                    resp = {"status":"error","error":"unauthorized"}
                else:
                    resp = handle_upload_report(body)
            elif action == "submit_expense":
                if role != "doctor":
                    resp = {"status":"error","error":"unauthorized"}
                else:
                    resp = handle_submit_expense(body)
            else:
                resp = {"status":"error","error":"unknown action"}
        except Exception as e:
            resp = {"status":"error","error": str(e)}
        self.wfile.write((json.dumps(resp) + "\n").encode())

# ---------------------------
# Auditor utilities (CLI)
# ---------------------------
def load_doctors():
    return read_json(DOCTORS_FILE, {})

def load_expenses():
    return read_json(EXPENSES_FILE, [])

def load_reports():
    return read_json(REPORTS_FILE, [])

def audit_list_doctors():
    docs = load_doctors()
    if not docs:
        print("No registered doctors.")
        return
    print("Doctors:")
    for did, info in docs.items():
        enc = info["dept_enc"]
        print(f"- {did} name='{info.get('name')}' dept_plain='{info.get('department_plain')}' enc_type={enc.get('type')} enc_info_keys={list(enc.keys())}")

def audit_keyword_search():
    docs = load_doctors()
    if not docs:
        print("no doctors")
        return
    q = input("Enter department keyword to search: ").strip()
    if not q:
        print("empty")
        return
    print("Searching...")
    # Paillier path: compute hash int of query and homomorphically compare
    import hashlib
    q_h = int.from_bytes(hashlib.sha256(q.encode()).digest(), "big")
    pub = PAI_PUB; priv = PAI_PRIV
    enc_q = pub.encrypt(q_h)
    for did, info in docs.items():
        enc = info["dept_enc"]
        if enc.get("type") == "Paillier":
            c = int(enc["ciphertext"]); exp = int(enc["exponent"])
            enc_doc = paillier.EncryptedNumber(pub, c, exp)
            diff = enc_doc - enc_q
            dec = priv.decrypt(diff)
            match = (dec == 0)
            print(f"  {did}: dept_plain='{info.get('department_plain')}' PAILLIER_match={match}")
        elif enc.get("type") == "SSE":
            # decrypt the SSE index using provided sse_key_b64
            try:
                sse_key = b64d(enc["sse_key_b64"])
                # sse_index is structure that client used: encrypted hash under AES-CBC (enc_payload)
                enc_index = enc["sse_index"]
                # decrypt to get raw hash bytes
                # reuse aes_decrypt_payload / but key length must be appropriate (we expect 32)
                raw = None
                try:
                    raw = aes_decrypt_payload(sse_key, enc_index)
                    # compare hashed query
                    q_sha = hashlib.sha256(q.encode()).digest()
                    matched = (raw == q_sha)
                except Exception:
                    matched = False
                print(f"  {did}: dept_plain='{info.get('department_plain')}' SSE_match={matched}")
            except Exception as e:
                print(f"  {did}: SSE-decrypt-error {e}")
        else:
            print(f"  {did}: unknown dept_enc type")

def rsa_homo_decrypt_sum(c_prod_int):
    n = RSA_PRIV.n
    d = RSA_PRIV.d
    g = RSA_HOMO_G
    # decrypt to get g^sum mod n
    m = pow(int(c_prod_int), d, n)
    # brute force discrete log for moderate sums
    max_iter = 500000
    acc = 1
    for k in range(0, max_iter+1):
        if acc == m:
            return k
        acc = (acc * g) % n
    return None

def audit_sum_expenses():
    exps = load_expenses()
    if not exps:
        print("no expenses")
        return
    # Paillier-sum if many are paillier
    has_paillier = any(e.get("alg") == "Paillier" for e in exps)
    if has_paillier:
        # multiply encrypted numbers (Paillier add) using phe library to demonstrate
        pub = PAI_PUB
        total_enc = None
        for e in exps:
            if e.get("alg") == "Paillier":
                c = int(e["cipher"]["ciphertext"])
                exp = int(e["cipher"]["exponent"])
                en = paillier.EncryptedNumber(pub, c, exp)
                if total_enc is None:
                    total_enc = en
                else:
                    total_enc = total_enc + en
        if total_enc is not None:
            total = PAI_PRIV.decrypt(total_enc)
            print(f"Paillier decrypted sum = {total}")

    # RSA-homomorphic product -> brute-force discrete log
    n = RSA_PUB.n
    c_prod = 1
    has_rsa_homo = False
    for e in exps:
        if e.get("alg") == "RSA-homo":
            has_rsa_homo = True
            c_prod = (c_prod * int(e["cipher"])) % n
    if has_rsa_homo:
        print(f"RSA-homo product ciphertext: {c_prod}")
        s = rsa_homo_decrypt_sum(c_prod)
        if s is None:
            print("RSA-homo: failed to recover sum (out of brute-force bound)")
        else:
            print(f"RSA-homo decrypted sum = {s}")

    # per-doctor sums (attempt both types)
    docs = load_doctors()
    if not docs:
        return
    for did in docs.keys():
        # paillier per-doctor
        total_p = None
        total_r_prod = 1
        has_r = False
        for e in exps:
            if e["doctor_id"] == did:
                if e.get("alg") == "Paillier":
                    en = paillier.EncryptedNumber(PAI_PUB, int(e["cipher"]["ciphertext"]), int(e["cipher"]["exponent"]))
                    total_p = en if total_p is None else total_p + en
                if e.get("alg") == "RSA-homo":
                    has_r = True
                    total_r_prod = (total_r_prod * int(e["cipher"])) % n
        if total_p is not None:
            val = PAI_PRIV.decrypt(total_p)
            print(f"  {did} Paillier-sum = {val}")
        if has_r:
            val = rsa_homo_decrypt_sum(total_r_prod)
            print(f"  {did} RSA-homo-sum = {val}")

def elgamal_verify(p, g, y, H_int, r, s):
    return pow(g, H_int, p) == (pow(y, r, p) * pow(r, s, p)) % p

def audit_verify_reports():
    records = load_reports()
    if not records:
        print("no reports")
        return
    docs = load_doctors()
    for rec in records:
        did = rec.get("doctor_id")
        docinfo = docs.get(did, {})
        sig_ok = False
        # attempt verification based on stored sig_pub and rec['sig']
        sig = rec.get("sig", {})
        registered_sig = docinfo.get("sig_pub", {})
        # load file if exists
        report_bytes = None
        try:
            if rec["saved_path"].endswith(".enc.json"):
                # encrypted blob stored; skip signature verify if no plaintext
                report_bytes = None
            else:
                with open(rec["saved_path"], "rb") as f:
                    report_bytes = f.read()
        except Exception:
            report_bytes = None
        timestamp = rec.get("timestamp","")
        # RSA
        if "rsa_pub_pem_b64" in registered_sig and "sig_b64" in sig:
            try:
                pub = RSA.import_key(b64d(registered_sig["rsa_pub_pem_b64"]))
                h = SHA256.new((report_bytes or b"") + timestamp.encode())
                pkcs1_15.new(pub).verify(h, b64d(sig["sig_b64"]))
                sig_ok = True
            except Exception:
                sig_ok = False
        # ECDSA
        elif "ecdsa_vk_b64" in registered_sig and "sig_b64" in sig:
            try:
                vk = VerifyingKey.from_string(b64d(registered_sig["ecdsa_vk_b64"]), curve=NIST256p)
                vk.verify(b64d(sig["sig_b64"]), (report_bytes or b"") + timestamp.encode(), hashfunc=SHA256.new().new)
                sig_ok = True
            except Exception:
                sig_ok = False
        # ElGamal
        elif "elgamal_pub" in registered_sig and "r" in sig and "s" in sig:
            try:
                el = registered_sig["elgamal_pub"]
                p = int(el["p"]); g = int(el["g"]); y = int(el["y"])
                r = int(sig["r"]); s = int(sig["s"])
                H = int.from_bytes(MD5.new((report_bytes or b"") + timestamp.encode()).digest(), "big") % (p-1)
                sig_ok = elgamal_verify(p,g,y,H,r,s)
            except Exception:
                sig_ok = False
        else:
            sig_ok = False
        # timestamp sanity
        ok_ts = False
        ts = None
        try:
            ts = datetime.fromisoformat(rec.get("timestamp"))
        except Exception:
            try:
                ts = datetime.strptime(rec.get("timestamp"), "%Y-%m-%dT%H:%M:%S.%f")
            except Exception:
                ts = None
        if ts:
            now = datetime.utcnow().replace(tzinfo=None)
            delta = (now - ts).total_seconds()
            ok_ts = (delta >= -300)  # not too far in future
        print(f"- report {os.path.basename(rec['saved_path'])} by {did} sig_ok={sig_ok} ts_ok={ok_ts} ts={rec.get('timestamp')}")

# ---------------------------
# Main: start server and auditor menu
# ---------------------------
def start_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), RequestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[server] listening on 127.0.0.1:{PORT}")
    return server

def auditor_menu():
    while True:
        print("\n[Auditor Menu]")
        print("1) List doctors")
        print("2) Keyword search doctors by dept")
        print("3) Sum expenses")
        print("4) Verify reports")
        print("5) Show public info")
        print("0) Exit")
        ch = input("Choice: ").strip()
        if ch == "1":
            audit_list_doctors()
        elif ch == "2":
            audit_keyword_search()
        elif ch == "3":
            audit_sum_expenses()
        elif ch == "4":
            audit_verify_reports()
        elif ch == "5":
            print(json.dumps(get_public_info(), indent=2))
        elif ch == "0":
            print("Exiting auditor menu.")
            break
        else:
            print("Unknown choice.")

if __name__ == "__main__":
    srv = start_server()
    auditor_menu()
