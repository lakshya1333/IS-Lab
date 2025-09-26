# encrypt via el gamaal, and sign using RSA for this


"""
ElGamal Encryption + RSA Signatures Transaction System
-----------------------------------------------------
- ElGamal for public-key encryption of payment details (merchant has ElGamal keypair)
- RSA digital signatures for signing SHA-512 hash of plaintext (customer)
- In-memory transaction store with roles: Customer, Merchant, Auditor
- No external file I/O. Console interaction only.

Security notes:
- This is an educational demo. Key sizes are small for speed; increase bits for real use.
- ElGamal implemented over a prime field. Plaintext is padded then converted to integer (< p).
"""

from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import random
import hashlib
from datetime import datetime, timezone, timedelta
import sys

# -------------------------------
# Helpers
# -------------------------------

def now_utc():
    return datetime.now(timezone.utc)


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

PADDING = b'::PAY'

# -------------------------------
# RSA signature utilities
# -------------------------------
class RSASigner:
    def __init__(self):
        self.key = None  # RSA key pair

    def generate_keys(self, bits=2048):
        self.key = RSA.generate(bits)
        print('[LOG] RSA keypair generated for customer (signing).')

    def sign(self, msg_bytes: bytes) -> bytes:
        h = SHA512.new(msg_bytes)
        signer = pkcs1_15.new(self.key)
        signature = signer.sign(h)
        return signature

    def public_key_pem(self) -> bytes:
        return self.key.publickey().export_key()

    def verify_with_pubkey(self, pubkey_pem: bytes, msg_bytes: bytes, signature: bytes) -> bool:
        pub = RSA.import_key(pubkey_pem)
        h = SHA512.new(msg_bytes)
        try:
            pkcs1_15.new(pub).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

# -------------------------------
# ElGamal encryption utilities
# -------------------------------
class ElGamalEnc:
    def __init__(self):
        self.p = None
        self.g = None
        self.x = None  # private
        self.h = None  # public = g^x mod p

    def generate_keys(self, bits=512):
        # generate a safe prime p and generator g
        # For demo: pick random prime p and set g=2 (assume generator)
        self.p = number.getPrime(bits)
        self.g = 2
        # private key x
        self.x = random.randint(2, self.p - 2)
        self.h = pow(self.g, self.x, self.p)
        print(f'[LOG] ElGamal keys generated for merchant (p size {self.p.bit_length()} bits).')

    def public_key(self):
        return {'p': self.p, 'g': self.g, 'h': self.h}

    def encrypt_with_pub(self, pub: dict, plaintext: bytes) -> tuple:
        p = pub['p']
        g = pub['g']
        h = pub['h']
        m = plaintext + PADDING
        m_int = bytes_to_int(m)
        if m_int >= p:
            raise ValueError('Plaintext too long for current ElGamal prime. Use smaller plaintext or larger key.')
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        c2 = (m_int * pow(h, k, p)) % p
        return (c1, c2)

    def decrypt(self, ctuple: tuple) -> bytes:
        c1, c2 = ctuple
        s = pow(c1, self.x, self.p)
        s_inv = number.inverse(s, self.p)
        m_int = (c2 * s_inv) % self.p
        m_bytes = int_to_bytes(m_int)
        if not m_bytes.endswith(PADDING):
            # padding not found -> decryption ambiguous or wrong
            return None
        return m_bytes[:-len(PADDING)]

# -------------------------------
# Transaction store & keys
# -------------------------------
TRANSACTIONS = []
MERCHANT_ELGAMAL = None
CUSTOMER_RSA_KEYS = {}  # name -> RSASigner (keeps private for demo); store public PEM for verification

# -------------------------------
# Role behaviors
# -------------------------------

def init_merchant(bits=512):
    global MERCHANT_ELGAMAL
    MERCHANT_ELGAMAL = ElGamalEnc()
    MERCHANT_ELGAMAL.generate_keys(bits=bits)


def role_customer_menu(customer_name='Customer'):
    # ensure RSA keys for customer
    if customer_name not in CUSTOMER_RSA_KEYS:
        rsa = RSASigner()
        rsa.generate_keys(bits=2048)
        CUSTOMER_RSA_KEYS[customer_name] = rsa
    else:
        rsa = CUSTOMER_RSA_KEYS[customer_name]

    if MERCHANT_ELGAMAL is None:
        print('[ERROR] Merchant ElGamal public key not initialized. Merchant must be initialized first.')
        return

    while True:
        print('\n--- CUSTOMER MENU ---')
        print('1) Create & Send transaction')
        print('2) Show my RSA public key (PEM)')
        print('0) Back')
        choice = input('Choose: ').strip()
        if choice == '0':
            return
        if choice == '2':
            print(rsa.public_key_pem().decode())
            continue
        if choice == '1':
            plaintext = input('Enter plaintext payment details: ').encode()
            # hash
            h = hashlib.sha512(plaintext).digest()
            # sign hash with RSA
            signature = rsa.sign(h)
            # encrypt plaintext with merchant's ElGamal public key
            pub = MERCHANT_ELGAMAL.public_key()
            try:
                ciphertext = MERCHANT_ELGAMAL.encrypt_with_pub(pub, plaintext)
            except ValueError as e:
                print('[ERROR]', e)
                continue
            tx = {
                'id': len(TRANSACTIONS) + 1,
                'from': customer_name,
                'to': 'Merchant',
                'ciphertext': ciphertext,
                'received_hash_hex': h.hex(),
                'signature': signature,
                'timestamp': now_utc(),
                'status': 'pending',
                'processed_at': None,
                'decrypted_plaintext': None,
                'computed_hash_hex': None,
                'hash_match': None,
                'signature_valid_at_processing': None
            }
            TRANSACTIONS.append(tx)
            print(f'[LOG] Transaction #{tx["id"]} created (encrypted with ElGamal)')
            continue
        print('Invalid choice.')


def role_merchant_menu():
    if MERCHANT_ELGAMAL is None:
        print('[ERROR] Merchant keys not initialized.')
        return
    while True:
        print('\n--- MERCHANT MENU ---')
        print('1) List pending transactions')
        print('2) Process all pending transactions')
        print('0) Back')
        choice = input('Choose: ').strip()
        if choice == '0':
            return
        if choice == '1':
            pending = [t for t in TRANSACTIONS if t['status'] == 'pending']
            if not pending:
                print('[LOG] No pending transactions.')
            else:
                for t in pending:
                    print(f"ID: {t['id']} from {t['from']} at {t['timestamp'].isoformat()} ciphertext=(c1 bits {t['ciphertext'][0].bit_length()}, c2 bits {t['ciphertext'][1].bit_length()})")
            continue
        if choice == '2':
            pending = [t for t in TRANSACTIONS if t['status'] == 'pending']
            if not pending:
                print('[LOG] No pending to process.')
                continue
            for t in pending:
                print(f"\n[MERCHANT] Processing Tx #{t['id']} from {t['from']}")
                decrypted = MERCHANT_ELGAMAL.decrypt(t['ciphertext'])
                if decrypted is None:
                    print(f"[WARN] Padding not present after decryption for Tx #{t['id']}. Marking processed but unverifiable.")
                    t['decrypted_plaintext'] = None
                    t['computed_hash_hex'] = None
                    t['hash_match'] = False
                    t['signature_valid_at_processing'] = False
                    t['status'] = 'processed'
                    t['processed_at'] = now_utc()
                    continue
                # compute hash
                computed_hash = hashlib.sha512(decrypted).digest()
                computed_hash_hex = computed_hash.hex()
                t['decrypted_plaintext'] = decrypted
                t['computed_hash_hex'] = computed_hash_hex
                t['hash_match'] = (computed_hash_hex == t['received_hash_hex'])
                # verify RSA signature using customer's public key
                customer = t['from']
                rsa = CUSTOMER_RSA_KEYS.get(customer)
                if not rsa:
                    print(f"[WARN] No RSA key for customer {customer}. Cannot verify signature.")
                    t['signature_valid_at_processing'] = False
                else:
                    pub_pem = rsa.public_key_pem()
                    sig_ok = rsa.verify_with_pubkey(pub_pem, bytes.fromhex(t['received_hash_hex']), t['signature'])
                    t['signature_valid_at_processing'] = bool(sig_ok)
                t['status'] = 'processed'
                t['processed_at'] = now_utc()
                print(f"[RESULT] Tx #{t['id']}: hash_match={t['hash_match']}, signature_valid={t['signature_valid_at_processing']}")
            continue
        print('Invalid choice.')


def role_auditor_menu():
    while True:
        print('\n--- AUDITOR MENU ---')
        print('1) List processed transactions (hashes only)')
        print('2) Verify RSA signatures on processed transactions')
        print('0) Back')
        choice = input('Choose: ').strip()
        if choice == '0':
            return
        if choice == '1':
            processed = [t for t in TRANSACTIONS if t['status'] == 'processed']
            if not processed:
                print('[LOG] No processed transactions yet.')
            else:
                for t in processed:
                    print(f"ID:{t['id']} from:{t['from']} time:{t['processed_at'].isoformat()} received_hash:{t['received_hash_hex']} computed_hash:{t.get('computed_hash_hex')} hash_match:{t.get('hash_match')}")
            continue
        if choice == '2':
            processed = [t for t in TRANSACTIONS if t['status'] == 'processed']
            if not processed:
                print('[LOG] No processed transactions.')
                continue
            for t in processed:
                customer = t['from']
                rsa = CUSTOMER_RSA_KEYS.get(customer)
                if not rsa:
                    print(f"ID {t['id']}: No public key for customer {customer}.")
                    continue
                pub_pem = rsa.public_key_pem()
                ok = rsa.verify_with_pubkey(pub_pem, bytes.fromhex(t['received_hash_hex']), t['signature'])
                print(f"ID {t['id']}: signature_valid={ok}")
            continue
        print('Invalid choice.')

# -------------------------------
# Initialization & Main Menu
# -------------------------------

def initialize_demo():
    init_merchant(bits=512)


def main_menu():
    initialize_demo()
    print('\nWelcome to the ElGamal+RSA Transaction System (demo)')
    while True:
        print('\n--- MAIN MENU ---')
        print('1) Customer')
        print('2) Merchant')
        print('3) Auditor')
        print('0) Exit')
        choice = input('Choose role: ').strip()
        if choice == '0':
            print('Bye.')
            sys.exit(0)
        elif choice == '1':
            name = input('Enter customer name (default "Customer"): ').strip() or 'Customer'
            role_customer_menu(name)
        elif choice == '2':
            role_merchant_menu()
        elif choice == '3':
            role_auditor_menu()
        else:
            print('Invalid choice.')

if __name__ == '__main__':
    main_menu()
