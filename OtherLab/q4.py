# medisecure_des_rsa.py
import datetime
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

# ---------- Helpers ----------
def sha512_obj(data: bytes):
    return SHA512.new(data)

# PKCS7-style padding but for DES blocksize=8
def pad_des(data: bytes) -> bytes:
    block = 8
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len]) * pad_len

def unpad_des(data: bytes) -> bytes:
    if len(data) == 0:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# ---------- MediSecure using DES + RSA ----------
class MediSecureDES:
    def __init__(self):
        # DES key (8 bytes). In real life you'd negotiate this securely.
        self.des_key = get_random_bytes(8)
        # RSA keypair for patient (for signing)
        self.patient_rsa_key = RSA.generate(2048)
        self.patient_public_key = self.patient_rsa_key.publickey()
        # In-memory records store
        self.records = []

    # Patient: encrypt with DES, sign SHA-512 of ciphertext with RSA
    def patient_upload(self, plaintext: str):
        print("\n[Patient] Uploading record...")
        data = plaintext.encode()

        # DES-CBC encryption
        iv = get_random_bytes(8)
        cipher = DES.new(self.des_key, DES.MODE_CBC, iv)
        ct = cipher.encrypt(pad_des(data))

        # Hash ciphertext using Crypto.Hash.SHA512
        h_obj = sha512_obj(ct)
        digest = h_obj.digest()

        # Sign hash with RSA private key (use Crypto.Hash object)
        signature = pkcs1_15.new(self.patient_rsa_key).sign(h_obj)

        record = {
            "ciphertext": ct,
            "iv": iv,
            "hash": digest,          # store digest bytes
            "signature": signature,  # RSA signature bytes
            "timestamp": datetime.datetime.now()
        }
        self.records.append(record)
        print("[Patient] Record uploaded (DES encrypted & RSA-signed).")

    # Doctor: decrypt DES, recompute hash, verify signature
    def doctor_process(self):
        print("\n[Doctor] Processing records...")
        for idx, rec in enumerate(self.records):
            print(f"\n-- Record {idx+1} --")
            ct = rec["ciphertext"]
            iv = rec["iv"]

            # Decrypt
            try:
                cipher = DES.new(self.des_key, DES.MODE_CBC, iv)
                pt_padded = cipher.decrypt(ct)
                plaintext = unpad_des(pt_padded).decode()
            except Exception as e:
                print("[Doctor] Decryption error:", e)
                continue

            # Recompute hash
            new_h = sha512_obj(ct).digest()
            if new_h != rec["hash"]:
                print("[Doctor] Hash mismatch! Integrity failed.")
                continue

            # Verify RSA signature of the hash (use SHA512 object)
            try:
                h_obj = sha512_obj(ct)
                pkcs1_15.new(self.patient_public_key).verify(h_obj, rec["signature"])
                sig_status = True
            except (ValueError, TypeError):
                sig_status = False

            print("[Doctor] Decrypted plaintext:", plaintext)
            print(f"[Doctor] Hash match: {new_h == rec['hash']}, Signature valid: {sig_status}")
            print("[Doctor] Processed timestamp:", rec["timestamp"])

    # Auditor: see only hashes and verify signatures (no plaintext)
    def auditor_audit(self):
        print("\n[Auditor] Auditing records...")
        for idx, rec in enumerate(self.records):
            print(f"\n-- Record {idx+1} --")
            print("Stored Hash (hex):", rec["hash"].hex())
            try:
                h_obj = sha512_obj(rec["ciphertext"])
                pkcs1_15.new(self.patient_public_key).verify(h_obj, rec["signature"])
                print("[Auditor] Signature valid.")
            except (ValueError, TypeError):
                print("[Auditor] Signature INVALID.")

# ---------- Main menu ----------
def main():
    ms = MediSecureDES()
    while True:
        print("\n===== MediSecure (DES + RSA) =====")
        print("1. Patient: Upload Record")
        print("2. Doctor: Process Records")
        print("3. Auditor: Audit Records")
        print("4. Exit")
        choice = input("Select role: ").strip()
        if choice == "1":
            text = input("Enter medical record text: ")
            ms.patient_upload(text)
        elif choice == "2":
            ms.doctor_process()
        elif choice == "3":
            ms.auditor_audit()
        elif choice == "4":
            print("Bye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
