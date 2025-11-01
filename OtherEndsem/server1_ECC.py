#!/usr/bin/env python3
"""
server.py
Privacy-preserving medical records server (ECC signatures)

Changes:
 - Uses ECDSA (ECC, P-256) verification instead of ElGamal
 - Registration expects 'ecc_pub_pem' (PEM string)
 - Upload report expects 'sig_b64' (base64 ECDSA signature) signed over (report_bytes + timestamp)
 - Audit verification uses ECDSA + SHA-256
"""

import os
import json
import threading
import socketserver
import base64
import time
from datetime import datetime, timezone
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import GCD
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from phe import paillier
import random
import math
import hashlib

DATA_DIR = "server_data"
DOCTORS_FILE = os.path.join(DATA_DIR, "doctors.json")
EXPENSES_FILE = os.path.join(DATA_DIR, "expenses.json")
REPORTS_FILE = os.path.join(DATA_DIR, "reports.json")
CONF_FILE = os.path.join(DATA_DIR, "config.json")
RSA_PRIV_FILE = os.path.join(DATA_DIR, "server_rsa_priv.pem")
RSA_PUB_FILE = os.path.join(DATA_DIR, "server_rsa_pub.pem")
PORT = 5000

lock = threading.Lock()

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)

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

def load_or_create_rsa():
    ensure_dirs()
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

def load_or_create_paillier():
    conf = read_json(CONF_FILE, {})
    if "paillier" not in conf:
        pubkey, privkey = paillier.generate_paillier_keypair()
        conf["paillier"] = {
            "n": str(pubkey.n),
            # storing p,q for demo only; not recommended in production
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

def load_or_create_config_rsa_homomorphic_base(rsa_pub):
    conf = read_json(CONF_FILE, {})
    n = rsa_pub.n
    if "rsa_homomorphic" not in conf:
        # pick base g coprime to n
        while True:
            g = random.randrange(2, n - 1)
            if GCD(g, n) == 1:
                break
        conf["rsa_homomorphic"] = {
            "g": str(g)
        }
        write_json(CONF_FILE, conf)
    conf = read_json(CONF_FILE, {})
    g = int(conf["rsa_homomorphic"]["g"])
    return g

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def init_storage():
    ensure_dirs()
    priv, pub = load_or_create_rsa()
    _ = load_or_create_paillier()
    if not os.path.exists(DOCTORS_FILE):
        write_json(DOCTORS_FILE, {})
    if not os.path.exists(EXPENSES_FILE):
        write_json(EXPENSES_FILE, [])
    if not os.path.exists(REPORTS_FILE):
        write_json(REPORTS_FILE, [])
    return priv, pub

RSA_PRIV, RSA_PUB = init_storage()
PAI_PUB, PAI_PRIV = load_or_create_paillier()
RSA_HOMO_G = load_or_create_config_rsa_homomorphic_base(RSA_PUB)

def get_public_info():
    return {
        "rsa_pub_pem_b64": b64e(RSA_PUB.export_key()),
        "rsa_n": str(RSA_PUB.n),
        "rsa_e": str(RSA_PUB.e),
        "paillier_n": str(PAI_PUB.n),
        "rsa_homo_g": str(RSA_HOMO_G),
    }

# -------------------- Handlers --------------------

def handle_register_doctor(body):
    # expect: {doctor_id, department_plain, dept_enc: {ciphertext, exponent}, ecc_pub_pem}
    doc_id = body.get("doctor_id","").strip()
    dept_plain = body.get("department_plain","").strip()
    dept_enc = body.get("dept_enc")
    ecc_pub_pem = body.get("ecc_pub_pem")
    if not doc_id or not doc_id.isalnum():
        return {"status":"error","error":"invalid doctor_id"}
    if not dept_plain:
        return {"status":"error","error":"invalid department"}
    if not dept_enc or "ciphertext" not in dept_enc or "exponent" not in dept_enc:
        return {"status":"error","error":"invalid dept_enc"}
    if not ecc_pub_pem:
        return {"status":"error","error":"missing ecc_pub_pem"}

    # basic check that ecc_pub_pem parses
    try:
        ECC.import_key(ecc_pub_pem)
    except Exception as e:
        return {"status":"error","error": f"invalid ECC public key: {e}"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
        doctors[doc_id] = {
            "department_plain": dept_plain,
            "dept_enc": {
                "ciphertext": str(int(dept_enc["ciphertext"])),
                "exponent": int(dept_enc["exponent"])
            },
            "ecc_pub_pem": ecc_pub_pem
        }
        write_json(DOCTORS_FILE, doctors)
    print(f"[server] registered doctor {doc_id} dept='{dept_plain}' (stored encrypted and plaintext)")
    return {"status":"ok"}

def handle_upload_report(body):
    # body: {doctor_id, filename, timestamp, md5_hex, sig_b64 OR sig:{r,s}, aes: {key_rsa_oaep_b64, nonce_b64, tag_b64, ct_b64}}
    doc_id = body.get("doctor_id","").strip()
    filename = os.path.basename(body.get("filename","").strip())
    timestamp = body.get("timestamp","").strip()
    md5_hex = body.get("md5_hex","").strip()
    aes = body.get("aes")
    if not doc_id or not filename or not timestamp or not md5_hex or not aes:
        return {"status":"error","error":"missing fields"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status":"error","error":"unknown doctor_id"}

    # decrypt AES key and decrypt ciphertext
    try:
        rsa_cipher = PKCS1_OAEP.new(RSA_PRIV)
        aes_key = rsa_cipher.decrypt(b64d(aes["key_rsa_oaep_b64"]))
        nonce = b64d(aes["nonce_b64"])
        tag = b64d(aes["tag_b64"])
        ct = b64d(aes["ct_b64"])
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        report_bytes = aes_cipher.decrypt_and_verify(ct, tag)
    except Exception as e:
        return {"status":"error","error":f"aes/rsa decrypt failed: {e}"}

    # verify MD5
    md5_check = hashlib.md5(report_bytes).hexdigest()
    if md5_check != md5_hex:
        print("[server] md5 mismatch (warning)")

    # verify signature:
    verified = False
    # Client signs: report_bytes + timestamp.encode()
    signed_message = report_bytes + timestamp.encode()
    # Prefer new field sig_b64 (base64 ECDSA signature); fallback to legacy sig dict (ElGamal)
    sig_b64 = body.get("sig_b64")
    if sig_b64:
        try:
            sig_bytes = b64d(sig_b64)
            ecc_pub_pem = doctors[doc_id]["ecc_pub_pem"]
            pub = ECC.import_key(ecc_pub_pem)
            h = SHA256.new(signed_message)
            verifier = DSS.new(pub, "fips-186-3")
            verifier.verify(h, sig_bytes)  # raises ValueError on bad sig
            verified = True
        except Exception as e:
            verified = False
    else:
        # Legacy ElGamal signature format {r,s} - we keep for compatibility
        sig = body.get("sig")
        if sig and isinstance(sig, dict) and "r" in sig and "s" in sig:
            # Cannot verify ElGamal here (we removed ElGamal-based logic). Mark unverified.
            verified = False

    # store file
    outdir = os.path.join(DATA_DIR, "reports")
    os.makedirs(outdir, exist_ok=True)
    savepath = os.path.join(outdir, f"{doc_id}_{int(time.time())}_{filename}")
    with open(savepath, "wb") as f:
        f.write(report_bytes)

    # record
    rec = {
        "doctor_id": doc_id,
        "filename": filename,
        "saved_path": savepath,
        "timestamp": timestamp,
        "md5_hex": md5_hex,
        "sig_b64": sig_b64 if sig_b64 else None,
        "legacy_sig": (sig if not sig_b64 else None),
        "verified": verified
    }
    with lock:
        records = read_json(REPORTS_FILE, [])
        records.append(rec)
        write_json(REPORTS_FILE, records)
    print(f"[server] report uploaded by {doc_id}, stored {savepath} verified={verified}")
    return {"status":"ok"}

def handle_submit_expense(body):
    doc_id = body.get("doctor_id","").strip()
    c = body.get("amount_ciphertext")
    if not doc_id or not doc_id.isalnum():
        return {"status":"error","error":"invalid doctor_id"}
    try:
        c_int = int(c)
    except:
        return {"status":"error","error":"invalid ciphertext"}
    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status":"error","error":"unknown doctor_id"}

    with lock:
        expenses = read_json(EXPENSES_FILE, [])
        expenses.append({"doctor_id": doc_id, "ciphertext": str(c_int)})
        write_json(EXPENSES_FILE, expenses)
    print(f"[server] expense ciphertext stored for {doc_id}")
    return {"status":"ok"}

# -------------------- Request handler --------------------

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
            if action == "get_public_info" or action == "get_public_info":
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

# -------------------- Auditor utilities --------------------

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
    h = int.from_bytes(hashlib.sha256(q.encode()).digest(), "big") % PAI_PUB.n
    enc_q = PAI_PUB.encrypt(h)
    print("Matching doctors (using Paillier equality on hashed dept):")
    for did, info in docs.items():
        enc = info["dept_enc"]
        c = int(enc["ciphertext"])
        exp = int(enc["exponent"])
        enc_doc = paillier.EncryptedNumber(PAI_PUB, c, exp)
        diff = enc_doc - enc_q
        dec = PAI_PRIV.decrypt(diff)
        match = (dec == 0)
        print(f"  {did}: dept_plain='{info['department_plain']}' enc_ciphertext={c} match={match}")

def rsa_homo_decrypt_sum(c_prod_int):
    n = RSA_PRIV.n
    d = RSA_PRIV.d
    g = RSA_HOMO_G
    # decrypt to get g^sum mod n
    m = pow(int(c_prod_int), d, n)
    # brute force discrete log for small sums
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
    n = RSA_PUB.n
    c_prod = 1
    for e in exps:
        c_prod = (c_prod * int(e["ciphertext"])) % n
    print(f"Product ciphertext (represents sum under RSA-in-exponent): {c_prod}")
    s = rsa_homo_decrypt_sum(c_prod)
    if s is None:
        print("sum decryption failed (exceeded search bound)")
    else:
        print(f"Decrypted sum of expenses = {s}")
    docs = load_doctors()
    if docs:
        print("Per-doctor sums:")
        for did in docs.keys():
            c_prod_d = 1
            count = 0
            for e in exps:
                if e["doctor_id"] == did:
                    c_prod_d = (c_prod_d * int(e["ciphertext"])) % n
                    count += 1
            if count == 0:
                continue
            s_d = rsa_homo_decrypt_sum(c_prod_d)
            print(f"  {did}: entries={count} product_ct={c_prod_d} sum={s_d}")

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
            ecc_pub_pem = docinfo.get("ecc_pub_pem")
            if ecc_pub_pem and rec.get("sig_b64"):
                try:
                    with open(rec["saved_path"], "rb") as f:
                        report_bytes = f.read()
                    signed_message = report_bytes + rec["timestamp"].encode()
                    sig_bytes = b64d(rec["sig_b64"])
                    pub = ECC.import_key(ecc_pub_pem)
                    h = SHA256.new(signed_message)
                    verifier = DSS.new(pub, "fips-186-3")
                    verifier.verify(h, sig_bytes)
                    ok_sig = True
                except Exception:
                    ok_sig = False
            else:
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
            # not in the future by more than 5 min
            ok_ts = (delta >= -300)
        print(f"- report by {did} file={os.path.basename(rec['saved_path'])} sig_ok={ok_sig} ts_ok={ok_ts} ts={rec['timestamp']} md5={rec['md5_hex']}")

def auditor_menu():
    while True:
        print("\n[Auditor Menu]")
        print("1) List doctors (show encrypted and plaintext dept)")
        print("2) Keyword search doctors by dept (Paillier)")
        print("3) Sum expenses (RSA-in-exponent demo)")
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
            print("bye")
            break
        else:
            print("invalid")

def start_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), RequestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[server] listening on 127.0.0.1:{PORT}")
    return server

if __name__ == "__main__":
    start_server()
    auditor_menu()
