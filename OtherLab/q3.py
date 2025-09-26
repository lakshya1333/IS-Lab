# Question (from your exam paper)

# You are tasked with developing a secure healthcare data management system called “MediSecure”.
# This system ensures that patients’ medical records are stored confidentially, accessed only by authorized users, and verified for authenticity.

# The system supports three types of users:

# Patients

# Doctors

# Auditors

# Each has specific roles and permissions.

# Crypto Mechanisms to Use

# AES symmetric encryption → to encrypt/decrypt medical records.

# RSA digital signatures → for authenticating users.

# SHA-512 hashing → for verifying record integrity.

import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

# =================== Helpers ===================
def sha512_hash(data: bytes):
    return SHA512.new(data)

# Padding for AES (PKCS7)
def pad(data: bytes):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes):
    return data[:-data[-1]]

# =================== Patient / Doctor / Auditor ===================
class MediSecure:
    def __init__(self):
        self.records = []  # Store transactions

        # Generate AES key (shared between patient & doctor)
        self.aes_key = get_random_bytes(16)

        # RSA keypair for Patient
        self.patient_rsa_key = RSA.generate(2048)
        self.patient_public_key = self.patient_rsa_key.publickey()

    # --------------- Patient ---------------
    def patient_upload(self, plaintext: str):
        print("\n[Patient] Uploading record...")
        data = plaintext.encode()

        # Encrypt with AES
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data))

        # Hash the ciphertext
        h = sha512_hash(ct_bytes)

        # Sign hash with RSA private key
        signature = pkcs1_15.new(self.patient_rsa_key).sign(h)

        record = {
            "ciphertext": ct_bytes,
            "iv": cipher.iv,
            "hash": h.digest(),
            "signature": signature,
            "timestamp": datetime.datetime.now(),
        }

        self.records.append(record)
        print("[Patient] Record uploaded successfully.")

    # --------------- Doctor ---------------
    def doctor_process(self):
        print("\n[Doctor] Processing records...")
        for idx, rec in enumerate(self.records):
            print(f"\n-- Record {idx+1} --")
            ct = rec["ciphertext"]
            iv = rec["iv"]

            # Decrypt with AES
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct)).decode()

            # Recompute hash
            new_hash = sha512_hash(ct).digest()

            # Verify hash consistency
            if new_hash != rec["hash"]:
                print("[Doctor] Hash mismatch! Integrity compromised.")
                continue

            # Verify RSA signature
            try:
                h = sha512_hash(ct)
                pkcs1_15.new(self.patient_public_key).verify(h, rec["signature"])
                print("[Doctor] Signature valid.")
            except (ValueError, TypeError):
                print("[Doctor] Invalid signature!")
                continue

            print("[Doctor] Decrypted Record:", pt)
            print("[Doctor] Record verified and stored with timestamp:", rec["timestamp"])

    # --------------- Auditor ---------------
    def auditor_audit(self):
        print("\n[Auditor] Auditing records...")
        for idx, rec in enumerate(self.records):
            print(f"\n-- Record {idx+1} --")
            print("Stored Hash:", rec["hash"].hex()[:64], "...")

            # Verify RSA signature without decrypting
            try:
                h = sha512_hash(rec["ciphertext"])
                pkcs1_15.new(self.patient_public_key).verify(h, rec["signature"])
                print("[Auditor] Signature valid.")
            except (ValueError, TypeError):
                print("[Auditor] Invalid signature!")

# =================== Main Menu ===================
def main():
    ms = MediSecure()

    while True:
        print("\n===== MediSecure Menu =====")
        print("1. Patient: Upload Record")
        print("2. Doctor: Process Records")
        print("3. Auditor: Audit Records")
        print("4. Exit")

        choice = input("Select role: ")

        if choice == "1":
            text = input("Enter medical record text: ")
            ms.patient_upload(text)
        elif choice == "2":
            ms.doctor_process()
        elif choice == "3":
            ms.auditor_audit()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()