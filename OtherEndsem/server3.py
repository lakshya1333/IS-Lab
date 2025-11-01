#!/usr/bin/env python3
"""
server_elgamal_paillier.py

Server supporting:
 - ElGamal (for AES-key encryption + expense homomorphic accumulation)
 - Paillier (for encrypted department search)
 - AES (EAX) for report payloads
 - SHA-256 for hashing (replaces MD5)

Protocol: line-based JSON requests over TCP:
  { "action": "...", "role": "...", "body": { ... } }

Actions:
 - get_public_info
 - register_doctor
 - upload_report
 - submit_expense

Run: python3 server_elgamal_paillier.py
"""

import os
import json
import threading
import socketserver
import base64
import time
import math
from datetime import datetime, timezone
from pathlib import Path

from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util import number
import hashlib
from phe import paillier

# --- Configuration & storage paths ---
DATA_DIR = "server_data"
DOCTORS_FILE = os.path.join(DATA_DIR, "doctors.json")
EXPENSES_FILE = os.path.join(DATA_DIR, "expenses.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports.json")
CONF_FILE = os.path.join(DATA_DIR, "config.json")
ELGAMAL_FILE = os.path.join(DATA_DIR, "server_elgamal.json")
PORT = 5000

# thread lock for safe file access
lock = threading.Lock()

# --- helpers ---
def ensure_dirs():
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    Path(os.path.join(DATA_DIR, "reports")).mkdir(parents=True, exist_ok=True)

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

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

# --- ElGamal (server key generation + persistence) ---
def load_or_create_elgamal(bits=512):
    """
    Create or load ElGamal key parameters stored in JSON:
      {p,g,y,x}
    We use small default bits (512) for speed in demos. Increase for production.
    """
    ensure_dirs()
    if os.path.exists(ELGAMAL_FILE):
        data = read_json(ELGAMAL_FILE, {})
        p = int(data["p"]); g = int(data["g"]); y = int(data["y"]); x = int(data["x"])
        print("[server] loaded existing ElGamal key.")
        return p, g, y, x
    # generate parameters
    print("[server] generating ElGamal keypair (this may take a few seconds)...")
    # Using PyCryptodome ElGamal.generate to ensure correct params
    key = ElGamal.generate(bits, get_random_bytes)
    p = int(key.p); g = int(key.g); y = int(key.y)
    # Crypto's ElGamal object has .x (private)
    try:
        x = int(key.x)
    except AttributeError:
        # If not present, generate private x randomly
        x = number.getRandomRange(2, p-2)
    write_json(ELGAMAL_FILE, {"p": str(p), "g": str(g), "y": str(y), "x": str(x)})
    print("[server] generated + saved ElGamal key.")
    return p, g, y, x

# --- Paillier keypair creation & persistence (for auditor/server search) ---
def load_or_create_paillier():
    conf = read_json(CONF_FILE, {})
    if "paillier" not in conf:
        print("[server] generating Paillier keypair (demo strength)...")
        pubkey, privkey = paillier.generate_paillier_keypair()
        conf["paillier"] = {
            "n": str(pubkey.n),
            # Note: private primes not exported here to avoid storing unnecessarily in clear;
            # but for demo we store them so server can also act as auditor when needed.
            "p": str(privkey.p),
            "q": str(privkey.q),
        }
        write_json(CONF_FILE, conf)
    conf = read_json(CONF_FILE, {})
    n = int(conf["paillier"]["n"])
    p = int(conf["paillier"]["p"])
    q = int(conf["paillier"]["q"])
    pubkey = paillier.PaillierPublicKey(n)
    privkey = paillier.PaillierPrivateKey(pubkey, p, q)
    return pubkey, privkey

# --- Storage init ---
def init_storage():
    ensure_dirs()
    # create empty files if not exist
    if not os.path.exists(DOCTORS_FILE):
        write_json(DOCTORS_FILE, {})
    if not os.path.exists(EXPENSES_FILE):
        write_json(EXPENSES_FILE, [])
    if not os.path.exists(REPORTS_FILE):
        write_json(REPORTS_FILE, [])
    # paillier keys created via load_or_create_paillier
    return

# initialize
init_storage()
P_ELGAMAL, G_ELGAMAL, Y_ELGAMAL, X_ELGAMAL = load_or_create_elgamal(bits=512)
PAI_PUB, PAI_PRIV = load_or_create_paillier()

# For expense homomorphic scheme we use ElGamal: clients should encrypt amounts as g^amount (mod p) and then ElGamal-encrypt that m.
# We'll store expense ciphertexts as {"c1":str,"c2":str}.

# --- Public info endpoint ---
def get_public_info():
    return {
        "elgamal_pub": {"p": str(P_ELGAMAL), "g": str(G_ELGAMAL), "y": str(Y_ELGAMAL)},
        "paillier_n": str(PAI_PUB.n)
    }

# --- Request Handlers ---
def handle_register_doctor(body):
    # body: {doctor_id, department_plain, dept_enc: {ciphertext, exponent}, elgamal_pub: {p,g,y}}
    doc_id = body.get("doctor_id","").strip()
    dept_plain = body.get("department_plain","").strip()
    dept_enc = body.get("dept_enc")
    elgamal_pub = body.get("elgamal_pub")
    if not doc_id or not doc_id.isalnum():
        return {"status":"error","error":"invalid doctor_id"}
    if not dept_plain:
        return {"status":"error","error":"invalid department"}
    if not dept_enc or "ciphertext" not in dept_enc or "exponent" not in dept_enc:
        return {"status":"error","error":"invalid dept_enc"}
    if not elgamal_pub or not all(k in elgamal_pub for k in ["p","g","y"]):
        return {"status":"error","error":"missing elgamal_pub"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
        doctors[doc_id] = {
            "department_plain": dept_plain,
            "dept_enc": {
                "ciphertext": str(int(dept_enc["ciphertext"])),
                "exponent": int(dept_enc["exponent"])
            },
            "elgamal_pub": {
                "p": str(int(elgamal_pub["p"])),
                "g": str(int(elgamal_pub["g"])),
                "y": str(int(elgamal_pub["y"]))
            }
        }
        write_json(DOCTORS_FILE, doctors)
    print(f"[server] registered doctor {doc_id} dept='{dept_plain}' (stored encrypted and plaintext)")
    return {"status":"ok"}

def handle_upload_report(body):
    """
    Expects:
      body = {
        doctor_id, filename, timestamp, sha256_hex,
        sig: {r,s},
        aes: {
          key_elgamal_json: JSON-string '{"c1":"..","c2":".."}' OR dict,
          nonce_b64, tag_b64, ct_b64
        }
      }
    """
    doc_id = body.get("doctor_id","").strip()
    filename = os.path.basename(body.get("filename","").strip())
    timestamp = body.get("timestamp","").strip()
    sha256_hex = body.get("sha256_hex","").strip()
    sig = body.get("sig")
    aes = body.get("aes")
    if not doc_id or not filename or not timestamp or not sha256_hex or not sig or not aes:
        return {"status":"error","error":"missing fields"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status":"error","error":"unknown doctor_id"}

    # AES key: ElGamal-encrypted under server ElGamal pub; decrypt using server private X_ELGAMAL
    try:
        key_enc = aes.get("key_elgamal_json")
        if isinstance(key_enc, str):
            key_enc_obj = json.loads(key_enc)
        else:
            key_enc_obj = key_enc
        c1 = int(key_enc_obj["c1"])
        c2 = int(key_enc_obj["c2"])
        # m = c2 * (c1^x)^{-1} mod p
        s = pow(c1, X_ELGAMAL, P_ELGAMAL)
        invs = inverse(s, P_ELGAMAL)
        m_int = (c2 * invs) % P_ELGAMAL
        # convert to bytes
        aes_key = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")
    except Exception as e:
        return {"status":"error","error":f"elgamal decrypt aes key failed: {e}"}

    # decrypt AES (EAX)
    try:
        nonce = b64d(aes["nonce_b64"])
        tag = b64d(aes["tag_b64"])
        ct = b64d(aes["ct_b64"])
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        report_bytes = cipher.decrypt_and_verify(ct, tag)
    except Exception as e:
        return {"status":"error","error":f"aes decrypt failed: {e}"}

    # verify SHA-256
    sha_check = hashlib.sha256(report_bytes).hexdigest()
    if sha_check != sha256_hex:
        print("[server] warning: sha256 mismatch (stored value may be tampered or client mismatch)")

    # persist report file
    outdir = os.path.join(DATA_DIR, "reports")
    os.makedirs(outdir, exist_ok=True)
    savepath = os.path.join(outdir, f"{doc_id}_{int(time.time())}_{filename}")
    with open(savepath, "wb") as f:
        f.write(report_bytes)

    # store metadata
    rec = {
        "doctor_id": doc_id,
        "filename": filename,
        "saved_path": savepath,
        "timestamp": timestamp,
        "sha256_hex": sha256_hex,
        "sig": {"r": str(int(sig["r"])), "s": str(int(sig["s"]))}
    }
    with lock:
        records = read_json(REPORTS_FILE, [])
        records.append(rec)
        write_json(REPORTS_FILE, records)
    print(f"[server] report uploaded by {doc_id}, stored {savepath}")
    return {"status":"ok"}

def handle_submit_expense(body):
    """
    Acceptance for an expense encrypted via ElGamal:
      body: { doctor_id, enc_amount: {"c1": "...", "c2": "..." } }
    (Clients should encode the amount as m = g^amount mod p, then ElGamal-encrypt m.)
    """
    doc_id = body.get("doctor_id","").strip()
    enc = body.get("enc_amount")
    if not doc_id or not doc_id.isalnum():
        return {"status":"error","error":"invalid doctor_id"}
    if not enc or "c1" not in enc or "c2" not in enc:
        return {"status":"error","error":"invalid enc_amount"}
    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status":"error","error":"unknown doctor_id"}

    with lock:
        exps = read_json(EXPENSES_FILE, [])
        exps.append({"doctor_id": doc_id, "c1": str(int(enc["c1"])), "c2": str(int(enc["c2"]))})
        write_json(EXPENSES_FILE, exps)
    print(f"[server] stored encrypted expense for {doc_id}")
    return {"status":"ok"}

# --- Auditing helpers ---
def load_doctors():
    return read_json(DOCTORS_FILE, {})

def load_expenses():
    return read_json(EXPENSES_FILE, [])

def load_reports():
    return read_json(REPORTS_FILE, [])

def audit_list_doctors():
    docs = load_doctors()
    print("Doctors:")
    for did, info in docs.items():
        enc = info["dept_enc"]
        print(f"- {did} dept_plain='{info['department_plain']}' enc_ciphertext={enc['ciphertext']} exponent={enc['exponent']}")

def audit_keyword_search():
    docs = load_doctors()
    if not docs:
        print("no doctors")
        return
    q = input("Enter department keyword to search: ").strip()
    if not q:
        print("empty")
        return
    h = int.from_bytes(hashlib.sha256(q.encode()).digest(), "big")
    pub = PAI_PUB
    priv = PAI_PRIV
    enc_q = pub.encrypt(h)
    print("Matching doctors (using Paillier equality on hashed dept):")
    for did, info in docs.items():
        enc = info["dept_enc"]
        c = int(enc["ciphertext"])
        exp = int(enc["exponent"])
        enc_doc = paillier.EncryptedNumber(pub, c, exp)
        diff = enc_doc - enc_q
        dec = priv.decrypt(diff)
        match = (dec == 0)
        print(f"  {did}: dept_plain='{info['department_plain']}' match={match}")

def elgamal_discrete_log(g, h, p, bound=200000):
    """
    Baby-step giant-step discrete log for g^x = h mod p, search 0..bound
    """
    m = int(math.ceil(math.sqrt(bound)))
    table = {}
    e = 1
    for j in range(m):
        if e not in table:
            table[e] = j
        e = (e * g) % p
    # compute g^{-m}
    inv_g = pow(g, -1, p)
    factor = pow(inv_g, m, p)
    y = h
    for i in range(m):
        if y in table:
            return i * m + table[y]
        y = (y * factor) % p
    return None

def audit_sum_expenses():
    exps = load_expenses()
    if not exps:
        print("no expenses")
        return
    # multiply ciphertexts component-wise to get encryption of product of plaintexts = product of g^{amount} => g^{sum}
    c1_prod = 1
    c2_prod = 1
    p = P_ELGAMAL
    for e in exps:
        c1_prod = (c1_prod * int(e["c1"])) % p
        c2_prod = (c2_prod * int(e["c2"])) % p
    print(f"[server] aggregated ciphertext (all): c1={c1_prod} c2={c2_prod}")
    # decrypt aggregated ciphertext using private x to get m = g^{sum} mod p
    s = pow(c1_prod, X_ELGAMAL, p)
    invs = inverse(s, p)
    m = (c2_prod * invs) % p
    # discrete log to find sum
    bound = int(input("Discrete-log bound to search for sum (e.g. 200000): ").strip() or "200000")
    s_val = elgamal_discrete_log(G_ELGAMAL, m, p, bound=bound)
    if s_val is None:
        print("[server] unable to recover sum within bound")
    else:
        print(f"[server] decrypted total sum = {s_val}")

    # per-doctor sums
    docs = load_doctors()
    if docs:
        print("Per-doctor sums:")
        for did in docs.keys():
            c1_d = 1
            c2_d = 1
            count = 0
            for e in exps:
                if e["doctor_id"] == did:
                    c1_d = (c1_d * int(e["c1"])) % p
                    c2_d = (c2_d * int(e["c2"])) % p
                    count += 1
            if count == 0:
                continue
            s = pow(c1_d, X_ELGAMAL, p)
            invs = inverse(s, p)
            m_d = (c2_d * invs) % p
            s_val = elgamal_discrete_log(G_ELGAMAL, m_d, p, bound=bound)
            print(f"  {did}: entries={count} sum={s_val}")

def elgamal_verify(p, g, y, H_int, r, s):
    # verify: g^H ≡ y^r * r^s (mod p)
    return pow(g, H_int, p) == (pow(y, r, p) * pow(r, s, p)) % p

def audit_verify_reports():
    records = load_reports()
    if not records:
        print("no reports")
        return
    doctors = load_doctors()
    for rec in records:
        did = rec["doctor_id"]
        docinfo = doctors.get(did)
        ok_sig = False
        ok_ts = False
        if docinfo:
            p_doc = int(docinfo["elgamal_pub"]["p"])
            g_doc = int(docinfo["elgamal_pub"]["g"])
            y_doc = int(docinfo["elgamal_pub"]["y"])
            r = int(rec["sig"]["r"])
            s = int(rec["sig"]["s"])
            try:
                with open(rec["saved_path"], "rb") as f:
                    report_bytes = f.read()
                H = int.from_bytes(hashlib.sha256(report_bytes + rec["timestamp"].encode()).digest(), "big") % (p_doc - 1)
                ok_sig = elgamal_verify(p_doc, g_doc, y_doc, H, r, s)
            except Exception:
                ok_sig = False
        # timestamp check
        try:
            ts = datetime.fromisoformat(rec["timestamp"])
        except:
            try:
                ts = datetime.strptime(rec["timestamp"], "%Y-%m-%dT%H:%M:%S.%f")
            except:
                ts = None
        if ts:
            now = datetime.utcnow().replace(tzinfo=None)
            delta = (now - ts).total_seconds()
            ok_ts = (delta >= -300)
        print(f"- report by {did} file={os.path.basename(rec['saved_path'])} sig_ok={ok_sig} ts_ok={ok_ts} ts={rec['timestamp']} sha256={rec.get('sha256_hex')}")

# --- Networking / Request handler ---
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
            resp = {"status":"error","error":str(e)}
        self.wfile.write((json.dumps(resp)+"\n").encode())

def start_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), RequestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[server] listening on 127.0.0.1:{PORT}")
    return server

# --- CLI for auditor operations while server runs ---
def auditor_menu():
    while True:
        print("\n[Auditor Menu]")
        print("1) List doctors")
        print("2) Keyword search doctors by dept (Paillier)")
        print("3) Sum expenses (ElGamal multiplicative scheme)")
        print("4) Verify reports and timestamps")
        print("5) Show server public info")
        print("0) Exit")
        ch = input("Select: ").strip()
        if ch == "1":
            audit_list_doctors()
        elif ch == "2":
            audit_keyword_search()
        elif ch == "3":
            audit_sum_expenses()
        elif ch == "4":
            audit_verify_reports()
        elif ch == "5":
            info = get_public_info()
            print(json.dumps(info, indent=2))
        elif ch == "0":
            break
        else:
            print("invalid")

# --- Main ---
if __name__ == "__main__":
    start_server()
    print("[server] server started. Type 'audit' to enter auditor console, 'quit' to stop.")
    while True:
        cmd = input(">> ").strip().lower()
        if cmd == "audit":
            auditor_menu()
        elif cmd in ("quit", "exit"):
            print("[server] shutting down.")
            break
        elif cmd == "":
            continue
        else:
            print("commands: audit | quit")
