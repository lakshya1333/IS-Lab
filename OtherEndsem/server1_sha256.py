import os
import json
import threading
import socketserver
import base64
import time
from datetime import datetime, timezone
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import GCD
from phe import paillier

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
        import random
        while True:
            g = random.randrange(2, n - 1)
            if GCD(g, n) == 1:
                break
        conf["rsa_homomorphic"] = {"g": str(g)}
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

def handle_register_doctor(body):
    doc_id = body.get("doctor_id", "").strip()
    dept_plain = body.get("department_plain", "").strip()
    dept_enc = body.get("dept_enc")
    elgamal_pub = body.get("elgamal_pub")
    if not doc_id or not doc_id.isalnum():
        return {"status": "error", "error": "invalid doctor_id"}
    if not dept_plain:
        return {"status": "error", "error": "invalid department"}
    if not dept_enc or "ciphertext" not in dept_enc or "exponent" not in dept_enc:
        return {"status": "error", "error": "invalid dept_enc"}
    if not elgamal_pub or not all(k in elgamal_pub for k in ["p", "g", "y"]):
        return {"status": "error", "error": "missing elgamal_pub"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
        doctors[doc_id] = {
            "department_plain": dept_plain,
            "dept_enc": {
                "ciphertext": str(int(dept_enc["ciphertext"])),
                "exponent": int(dept_enc["exponent"]),
            },
            "elgamal_pub": {
                "p": str(int(elgamal_pub["p"])),
                "g": str(int(elgamal_pub["g"])),
                "y": str(int(elgamal_pub["y"])),
            },
        }
        write_json(DOCTORS_FILE, doctors)
    print(f"[server] registered doctor {doc_id} dept='{dept_plain}'")
    return {"status": "ok"}

def handle_upload_report(body):
    # body: {doctor_id, filename, timestamp, sha256_hex, sig, aes}
    doc_id = body.get("doctor_id", "").strip()
    filename = os.path.basename(body.get("filename", "").strip())
    timestamp = body.get("timestamp", "").strip()
    sha256_hex = body.get("sha256_hex", "").strip()
    sig = body.get("sig")
    aes = body.get("aes")
    if not doc_id or not filename or not timestamp or not sha256_hex or not sig or not aes:
        return {"status": "error", "error": "missing fields"}

    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status": "error", "error": "unknown doctor_id"}

    # decrypt AES key
    try:
        rsa_cipher = PKCS1_OAEP.new(RSA_PRIV)
        aes_key = rsa_cipher.decrypt(b64d(aes["key_rsa_oaep_b64"]))
        nonce = b64d(aes["nonce_b64"])
        tag = b64d(aes["tag_b64"])
        ct = b64d(aes["ct_b64"])
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        report_bytes = aes_cipher.decrypt_and_verify(ct, tag)
    except Exception as e:
        return {"status": "error", "error": f"aes/rsa decrypt failed: {e}"}

    # verify SHA-256 hash
    import hashlib
    sha_check = hashlib.sha256(report_bytes).hexdigest()
    if sha_check != sha256_hex:
        print("[server] SHA256 mismatch")

    # store file
    outdir = os.path.join(DATA_DIR, "reports")
    os.makedirs(outdir, exist_ok=True)
    savepath = os.path.join(outdir, f"{doc_id}_{int(time.time())}_{filename}")
    with open(savepath, "wb") as f:
        f.write(report_bytes)

    # store record
    rec = {
        "doctor_id": doc_id,
        "filename": filename,
        "saved_path": savepath,
        "timestamp": timestamp,
        "sha256_hex": sha256_hex,
        "sig": {"r": str(int(sig["r"])), "s": str(int(sig["s"]))},
    }
    with lock:
        records = read_json(REPORTS_FILE, [])
        records.append(rec)
        write_json(REPORTS_FILE, records)
    print(f"[server] report uploaded by {doc_id}, stored {savepath}")
    return {"status": "ok"}

def handle_submit_expense(body):
    doc_id = body.get("doctor_id", "").strip()
    c = body.get("amount_ciphertext")
    if not doc_id or not doc_id.isalnum():
        return {"status": "error", "error": "invalid doctor_id"}
    try:
        c_int = int(c)
    except:
        return {"status": "error", "error": "invalid ciphertext"}
    with lock:
        doctors = read_json(DOCTORS_FILE, {})
    if doc_id not in doctors:
        return {"status": "error", "error": "unknown doctor_id"}

    with lock:
        expenses = read_json(EXPENSES_FILE, [])
        expenses.append({"doctor_id": doc_id, "ciphertext": str(c_int)})
        write_json(EXPENSES_FILE, expenses)
    print(f"[server] expense ciphertext stored for {doc_id}")
    return {"status": "ok"}

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
                resp = {"status": "ok", "data": get_public_info()}
            elif action == "register_doctor":
                resp = handle_register_doctor(body) if role == "doctor" else {"status": "error", "error": "unauthorized"}
            elif action == "upload_report":
                resp = handle_upload_report(body) if role == "doctor" else {"status": "error", "error": "unauthorized"}
            elif action == "submit_expense":
                resp = handle_submit_expense(body) if role == "doctor" else {"status": "error", "error": "unauthorized"}
            else:
                resp = {"status": "error", "error": "unknown action"}
        except Exception as e:
            resp = {"status": "error", "error": str(e)}
        self.wfile.write((json.dumps(resp) + "\n").encode())

def start_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), RequestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[server] listening on 127.0.0.1:{PORT}")
    return server

# Auditor utilities
def load_doctors():
    return read_json(DOCTORS_FILE, {})

def load_expenses():
    return read_json(EXPENSES_FILE, [])

def load_reports():
    return read_json(REPORTS_FILE, [])

def audit_verify_reports():
    import hashlib
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
            p = int(docinfo["elgamal_pub"]["p"])
            g = int(docinfo["elgamal_pub"]["g"])
            y = int(docinfo["elgamal_pub"]["y"])
            r = int(rec["sig"]["r"])
            s = int(rec["sig"]["s"])
            try:
                with open(rec["saved_path"], "rb") as f:
                    report_bytes = f.read()
                H = int.from_bytes(hashlib.sha256(report_bytes + rec["timestamp"].encode()).digest(), "big") % (p - 1)
                ok_sig = (pow(g, H, p) == (pow(y, r, p) * pow(r, s, p)) % p)
            except Exception:
                ok_sig = False
        # timestamp check
        try:
            ts = datetime.fromisoformat(rec["timestamp"])
        except:
            ts = None
        if ts:
            now = datetime.utcnow().replace(tzinfo=None)
            delta = (now - ts).total_seconds()
            ok_ts = (delta >= -300)
        print(f"- report by {did} file={os.path.basename(rec['saved_path'])} sig_ok={ok_sig} ts_ok={ok_ts} ts={rec['timestamp']} sha256={rec['sha256_hex']}")

# Keep the rest (auditor menu, etc.) as is — unchanged.
