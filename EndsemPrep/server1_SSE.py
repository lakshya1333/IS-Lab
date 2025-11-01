# instead of PKSE(pailler) SSE is used


import os
import json
import threading
import socketserver
import base64
import time
from datetime import datetime, timezone
import hashlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import GCD

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

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

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

def load_or_create_config_rsa_homomorphic_base(rsa_pub):
    conf = read_json(CONF_FILE, {})
    n = rsa_pub.n
    if "rsa_homomorphic" not in conf:
        import random
        while True:
            g = random.randrange(2, n - 1)
            if GCD(g, n) == 1:
                break
        conf["rsa_homomorphic"] = {"g": str(g)}
        write_json(CONF_FILE, conf)
    conf = read_json(CONF_FILE, {})
    return int(conf["rsa_homomorphic"]["g"])

def init_storage():
    ensure_dirs()
    priv, pub = load_or_create_rsa()
    if not os.path.exists(DOCTORS_FILE):
        write_json(DOCTORS_FILE, {})
    if not os.path.exists(EXPENSES_FILE):
        write_json(EXPENSES_FILE, [])
    if not os.path.exists(REPORTS_FILE):
        write_json(REPORTS_FILE, [])
    return priv, pub

RSA_PRIV, RSA_PUB = init_storage()
RSA_HOMO_G = load_or_create_config_rsa_homomorphic_base(RSA_PUB)

# === Server Public Info ===
def get_public_info():
    return {
        "rsa_pub_pem_b64": b64e(RSA_PUB.export_key()),
        "rsa_n": str(RSA_PUB.n),
        "rsa_e": str(RSA_PUB.e),
        "rsa_homo_g": str(RSA_HOMO_G),
    }

# === Registration using SSE (AES-based Searchable Encryption) ===
def handle_register_doctor(body):
    """
    body: {
      doctor_id, department_plain,
      sse_index: {iv_b64, ct_b64},
      sse_key_b64: key used for encryption,
      elgamal_pub: {p,g,y}
    }
    """
    doc_id = body.get("doctor_id","").strip()
    dept_plain = body.get("department_plain","").strip()
    sse_index = body.get("sse_index")
    sse_key_b64 = body.get("sse_key_b64")
    elgamal_pub = body.get("elgamal_pub")

    if not doc_id or not doc_id.isalnum():
        return {"status":"error","error":"invalid doctor_id"}
    if not dept_plain:
        return {"status":"error","error":"invalid department"}
    if not sse_index or "iv_b64" not in sse_index or "ct_b64" not in sse_index:
        return {"status":"error","error":"missing SSE index"}
    if not sse_key_b64:
        return {"status":"error","error":"missing SSE key"}
    if not elgamal_pub or not all(k in elgamal_pub for k in ["p","g","y"]):
        return {"status":"error","error":"missing elgamal_pub"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
        doctors[doc_id] = {
            "department_plain": dept_plain,
            "sse_index": sse_index,
            "sse_key_b64": sse_key_b64,
            "elgamal_pub": elgamal_pub
        }
        write_json(DOCTORS_FILE, doctors)
    print(f"[server] Registered doctor {doc_id} with SSE-encrypted department '{dept_plain}'")
    return {"status":"ok"}

# === Report upload (same as before) ===
def handle_upload_report(body):
    doc_id = body.get("doctor_id","").strip()
    filename = os.path.basename(body.get("filename","").strip())
    timestamp = body.get("timestamp","").strip()
    md5_hex = body.get("md5_hex","").strip()
    sig = body.get("sig")
    aes = body.get("aes")
    if not doc_id or not filename or not timestamp or not md5_hex or not sig or not aes:
        return {"status":"error","error":"missing fields"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status":"error","error":"unknown doctor_id"}

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

    md5_check = hashlib.md5(report_bytes).hexdigest()
    if md5_check != md5_hex:
        print("[server] md5 mismatch")

    outdir = os.path.join(DATA_DIR, "reports")
    os.makedirs(outdir, exist_ok=True)
    savepath = os.path.join(outdir, f"{doc_id}_{int(time.time())}_{filename}")
    with open(savepath, "wb") as f:
        f.write(report_bytes)

    rec = {
        "doctor_id": doc_id,
        "filename": filename,
        "saved_path": savepath,
        "timestamp": timestamp,
        "md5_hex": md5_hex,
        "sig": {"r": str(int(sig["r"])), "s": str(int(sig["s"]))}
    }
    with lock:
        records = read_json(REPORTS_FILE, [])
        records.append(rec)
        write_json(REPORTS_FILE, records)
    print(f"[server] Report uploaded by {doc_id}, stored {savepath}")
    return {"status":"ok"}

# === Expense submission (unchanged) ===
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

# === SSE keyword search (auditor) ===
def audit_keyword_search():
    docs = read_json(DOCTORS_FILE, {})
    if not docs:
        print("no doctors")
        return
    q = input("Enter department keyword to search: ").strip()
    if not q:
        print("empty")
        return
    print("Performing SSE keyword match...")
    q_hash = hashlib.sha256(q.encode()).digest()
    for did, info in docs.items():
        try:
            sse_key = b64d(info["sse_key_b64"])
            iv = b64d(info["sse_index"]["iv_b64"])
            ct = b64d(info["sse_index"]["ct_b64"])
            cipher = AES.new(sse_key, AES.MODE_CBC, iv)
            enc_q = cipher.encrypt(pad(q_hash, AES.block_size))
            match = (enc_q == ct)
            print(f"  {did}: dept='{info['department_plain']}' match={match}")
        except Exception as e:
            print(f"  {did}: error {e}")

# === Homomorphic expense audit ===
def rsa_homo_decrypt_sum(c_prod_int):
    n = RSA_PRIV.n
    d = RSA_PRIV.d
    g = RSA_HOMO_G
    m = pow(int(c_prod_int), d, n)
    max_iter = 500000
    acc = 1
    for k in range(0, max_iter+1):
        if acc == m:
            return k
        acc = (acc * g) % n
    return None

def audit_sum_expenses():
    exps = read_json(EXPENSES_FILE, [])
    if not exps:
        print("no expenses")
        return
    n = RSA_PUB.n
    c_prod = 1
    for e in exps:
        c_prod = (c_prod * int(e["ciphertext"])) % n
    print(f"Product ciphertext (RSA-in-exponent): {c_prod}")
    s = rsa_homo_decrypt_sum(c_prod)
    print(f"Decrypted sum = {s}")

# === Report verification ===
def elgamal_verify(p, g, y, H_int, r, s):
    return pow(g, H_int, p) == (pow(y, r, p) * pow(r, s, p)) % p

def audit_verify_reports():
    records = read_json(REPORTS_FILE, [])
    if not records:
        print("no reports")
        return
    doctors = read_json(DOCTORS_FILE, {})
    for rec in records:
        did = rec["doctor_id"]
        docinfo = doctors.get(did)
        ok_sig = False
        ok_ts = False
        if docinfo:
            p = int(docinfo["elgamal_pub"]["p"])
            g = int(docinfo["elgamal_pub"]["g"])
            y = int(docinfo["elgamal_pub"]["y"])
            r = int(rec["sig"]["r"])
            s = int(rec["sig"]["s"])
            try:
                with open(rec["saved_path"], "rb") as f:
                    report_bytes = f.read()
                H = int.from_bytes(hashlib.md5(report_bytes + rec["timestamp"].encode()).digest(), "big") % (p - 1)
                ok_sig = elgamal_verify(p, g, y, H, r, s)
            except Exception:
                ok_sig = False
        try:
            ts = datetime.fromisoformat(rec["timestamp"])
            now = datetime.utcnow().replace(tzinfo=None)
            delta = (now - ts).total_seconds()
            ok_ts = (delta >= -300)
        except:
            ok_ts = False
        print(f"- {did}: sig_ok={ok_sig}, ts_ok={ok_ts}, file={rec['filename']}")

# === Networking ===
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
                resp = handle_upload_report(body)
            elif action == "submit_expense":
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

# === Auditor Menu ===
def auditor_menu():
    while True:
        print("\n[Auditor Menu]")
        print("1) List doctors")
        print("2) Search doctors by department (SSE)")
        print("3) Sum expenses")
        print("4) Verify reports")
        print("5) Show server public info")
        print("0) Exit")
        ch = input("Select: ").strip()
        if ch == "1":
            docs = read_json(DOCTORS_FILE, {})
            for did, info in docs.items():
                print(f"- {did}: dept='{info['department_plain']}'")
        elif ch == "2":
            audit_keyword_search()
        elif ch == "3":
            audit_sum_expenses()
        elif ch == "4":
            audit_verify_reports()
        elif ch == "5":
            print(json.dumps(get_public_info(), indent=2))
        elif ch == "0":
            print("bye")
            break
        else:
            print("invalid")

if __name__ == "__main__":
    start_server()
    auditor_menu()
