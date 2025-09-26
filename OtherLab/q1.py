# - Use the Rabin cryptosystem for public-key encryption of payment details (plaintext strings like "Send 55000 to Bob using Mastercard 3048330330393783"). T

# - Use the ElGamal signature scheme for the customer to digitally sign the SHA-512 hash of the plaintext payment details.

# - Implement a store for transactions, with roles for Customer, Merchant, and Auditor via interactive menus:
#   - Customer: Create and "send" a transaction by encrypting the details (Rabin), signing the SHA-512 hash (ElGamal), and recording it in history
#   - Merchant: Process all pending transactions by decrypting (Rabin, finding the valid root), computing the SHA-512 hash of the decrypted plaintext, verifying it matches the received hash, and verifying the ElGamal signature on the received hash. Record processing resultsand mark as processed.
#   - Auditor: View only the received and computed hashes for processed transactions (to check consistency without seeing plaintext), and separately verify ElGamal signatures on the received hashes using the customer's public key.
# . Use timestamps from

# - Ensure the system demonstrates confidentiality (only merchant decrypts), integrity (hash matching), and auditability (signatures verifiable without plaintext). Do not use external files or I/O beyond console input/output.



"""
Rabin + ElGamal Transaction System
----------------------------------
- Rabin for public-key encryption of payment details (merchant has Rabin keypair)
- ElGamal digital signatures for signing SHA-512 hash of plaintext (customer)
- In-memory transaction store with roles: Customer, Merchant, Auditor
- No external file I/O. Console interaction only.

Notes:
- Uses simple message padding to disambiguate Rabin roots (adds b"::PAY" suffix).
- This is an educational/demo implementation. Do NOT use for production.
"""

from Crypto.Util import number
import random
import hashlib
from datetime import datetime, timezone, timedelta
import sys

# -------------------------------
# Helper functions
# -------------------------------

def now_utc():
    return datetime.now(timezone.utc)


def int_to_bytes(i: int) -> bytes:
    # big-endian
    return i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def sha512_bytes(msg: bytes) -> bytes:
    return hashlib.sha512(msg).digest()


def sha512_hex(msg: bytes) -> str:
    return hashlib.sha512(msg).hexdigest()


def hash_message_to_int(msg: bytes, p: int) -> int:
    # Convert SHA-512 digest to integer reduced modulo p
    h = sha512_bytes(msg)
    return int.from_bytes(h, 'big') % p

# -------------------------------
# ElGamal signature (adapted from provided snippet)
# -------------------------------
class ElGamalSignature:
    def __init__(self):
        self.public_key = None  # (p, g, h)
        self.private_key = None

    def generate_keys(self, bits=512):
        p = number.getPrime(bits)
        g = 2
        x = random.randint(2, p - 2)
        h = pow(g, x, p)
        self.public_key = (p, g, h)
        self.private_key = x
        print("[LOG] ElGamal keys generated for customer.")

    def sign(self, msg: bytes):
        p, g, h = self.public_key
        x = self.private_key
        m = hash_message_to_int(msg, p)
        k = random.randint(2, p - 2)
        while number.GCD(k, p - 1) != 1:
            k = random.randint(2, p - 2)
        r = pow(g, k, p)
        k_inv = number.inverse(k, p - 1)
        s = (k_inv * (m - x * r)) % (p - 1)
        return (r, s)

    def verify(self, msg: bytes, signature: tuple):
        p, g, h = self.public_key
        r, s = signature
        if not (0 < r < p):
            return False
        m = hash_message_to_int(msg, p)
        left_side = (pow(h, r, p) * pow(r, s, p)) % p
        right_side = pow(g, m, p)
        return left_side == right_side

# -------------------------------
# Rabin cryptosystem utilities
# -------------------------------

def gen_rabin(bits=512):
    # Generate primes p,q ≡ 3 (mod 4)
    while True:
        p = number.getPrime(bits // 2)
        if p % 4 == 3:
            break
    while True:
        q = number.getPrime(bits // 2)
        if q % 4 == 3 and q != p:
            break
    n = p * q
    return {
        'n': n,
        'p': p,
        'q': q,
        'created': now_utc(),
        'expires': now_utc() + timedelta(days=365),
        'revoked': False
    }


def rabin_encrypt(n: int, plaintext: bytes, padding=b'::PAY') -> int:
    # Simple padding to help root identification
    m = plaintext + padding
    m_int = bytes_to_int(m)
    if m_int >= n:
        raise ValueError('Message too long for RSA modulus size. Reduce message length or increase key size.')
    c = pow(m_int, 2, n)
    return c


def rabin_decrypt(n: int, p: int, q: int, c: int, padding=b'::PAY') -> list:
    # compute roots modulo p and q (since p,q ≡ 3 (mod 4))
    # mp = c^{(p+1)/4} mod p
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    # four combinations via Chinese Remainder Theorem
    # use standard CRT combining
    def crt(a1, n1, a2, n2):
        m1 = n1
        m2 = n2
        inv_m1 = number.inverse(m1, m2)
        inv_m2 = number.inverse(m2, m1)
        x = (a1 * m2 * inv_m2 + a2 * m1 * inv_m1) % (m1 * m2)
        return x

    roots = []
    for s1 in (mp, (-mp) % p):
        for s2 in (mq, (-mq) % q):
            r = crt(s1, p, s2, q)
            roots.append(r)
    # remove duplicates
    unique_roots = list({r for r in roots})
    # convert to bytes and check padding in caller
    return unique_roots

# -------------------------------
# Transaction store and roles
# -------------------------------
KS = {}  # Rabin key store indexed by id (e.g., 'Merchant')
TRANSACTIONS = []  # list of transaction dicts
CUSTOMER_KEYS = {}  # store customer's elgamal public key and optionally id

PADDING = b'::PAY'


def create_rabin_for_merchant(merchant_id='Merchant', bits=512):
    KS[merchant_id] = gen_rabin(bits)
    print(f"[LOG] Created Rabin keypair for {merchant_id} (n size ~{bits} bits)")


def get_merchant_public(merchant_id='Merchant'):
    r = KS.get(merchant_id)
    if not r or r['revoked']:
        return None
    return {'n': r['n'], 'expires': r['expires']}


def get_merchant_private(merchant_id='Merchant'):
    r = KS.get(merchant_id)
    if not r or r['revoked']:
        return None
    return {'p': r['p'], 'q': r['q']}

# -------------------------------
# Interactive role functions
# -------------------------------

def role_customer_menu(customer_name='Customer'):
    # Ensure customer has ElGamal keys
    if customer_name not in CUSTOMER_KEYS:
        eg = ElGamalSignature()
        eg.generate_keys(bits=512)
        CUSTOMER_KEYS[customer_name] = eg
    else:
        eg = CUSTOMER_KEYS[customer_name]

    merchant_pub = get_merchant_public('Merchant')
    if not merchant_pub:
        print('[ERROR] Merchant public key not found. Merchant must be initialized first.')
        return

    while True:
        print('\n--- CUSTOMER MENU ---')
        print('1) Create & Send Transaction')
        print('2) View my public key')
        print('0) Back')
        choice = input('Choose: ').strip()
        if choice == '0':
            return
        if choice == '2':
            p, g, h = eg.public_key
            print('Customer ElGamal public key (p, g, h) sizes:', p.bit_length(), g, h.bit_length())
            continue
        if choice == '1':
            plaintext = input('Enter plaintext payment details (e.g. "Send 55000 to Bob using Mastercard 3048..."): ').encode()
            # compute SHA-512 hash
            msg_hash = sha512_bytes(plaintext)
            msg_hash_hex = msg_hash.hex()
            # sign the hash
            signature = eg.sign(msg_hash)
            # encrypt plaintext with merchant's Rabin public key
            n = merchant_pub['n']
            try:
                ciphertext = rabin_encrypt(n, plaintext, padding=PADDING)
            except ValueError as e:
                print('[ERROR]', e)
                continue
            tx = {
                'id': len(TRANSACTIONS) + 1,
                'from': customer_name,
                'to': 'Merchant',
                'ciphertext': ciphertext,
                'received_hash_hex': msg_hash_hex,
                'signature': signature,
                'timestamp': now_utc(),
                'status': 'pending',
                'processed_at': None,
                # fields to be filled by merchant:
                'decrypted_plaintext': None,  # merchant should set but we will omit printing for auditors
                'computed_hash_hex': None,
                'hash_match': None,
                'signature_valid_at_processing': None
            }
            TRANSACTIONS.append(tx)
            print(f'[LOG] Transaction #{tx["id"]} created and recorded. (ciphertext stored, hash & signature attached)')
            continue
        print('Invalid choice.')


def role_merchant_menu(merchant_id='Merchant'):
    priv = get_merchant_private(merchant_id)
    if not priv:
        print('[ERROR] Merchant private key not available. Initialize merchant first.')
        return
    p = priv['p']
    q = priv['q']
    n = KS[merchant_id]['n']

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
                    print(f"ID: {t['id']} from {t['from']} at {t['timestamp'].isoformat()} (ciphertext int len {t['ciphertext'].bit_length()} bits)")
            continue
        if choice == '2':
            pending = [t for t in TRANSACTIONS if t['status'] == 'pending']
            if not pending:
                print('[LOG] No pending to process.')
                continue
            for t in pending:
                print(f"\n[MERCHANT] Processing Tx #{t['id']} from {t['from']}")
                c = t['ciphertext']
                roots = rabin_decrypt(n, p, q, c, padding=PADDING)
                found = False
                recovered_plaintext = None
                for r in roots:
                    try:
                        pt_bytes = int_to_bytes(r)
                        if pt_bytes.endswith(PADDING):
                            # remove padding
                            recovered_plaintext = pt_bytes[:-len(PADDING)]
                            found = True
                            break
                    except Exception:
                        continue
                if not found:
                    print(f"[WARN] Could not identify correct Rabin root for Tx #{t['id']} (padding mismatch).")
                    t['decrypted_plaintext'] = None
                    t['computed_hash_hex'] = None
                    t['hash_match'] = False
                    t['signature_valid_at_processing'] = False
                    t['status'] = 'processed'
                    t['processed_at'] = now_utc()
                    continue
                # compute hash of decrypted plaintext
                computed_hash = sha512_bytes(recovered_plaintext)
                computed_hash_hex = computed_hash.hex()
                t['decrypted_plaintext'] = recovered_plaintext  # merchant stores it internally
                t['computed_hash_hex'] = computed_hash_hex
                # check if matches received hash
                t['hash_match'] = (computed_hash_hex == t['received_hash_hex'])
                # verify signature on the received hash using customer's public key
                customer = t['from']
                eg = CUSTOMER_KEYS.get(customer)
                if not eg:
                    print(f"[WARN] No ElGamal public key for customer {customer}. Signature cannot be verified.")
                    t['signature_valid_at_processing'] = False
                else:
                    # The signature was created on the raw SHA-512 bytes. Use the received_hash_hex -> bytes
                    received_hash_bytes = bytes.fromhex(t['received_hash_hex'])
                    sig_valid = eg.verify(received_hash_bytes, t['signature'])
                    t['signature_valid_at_processing'] = bool(sig_valid)
                t['status'] = 'processed'
                t['processed_at'] = now_utc()
                print(f"[RESULT] Tx #{t['id']}: hash_match={t['hash_match']}, signature_valid={t['signature_valid_at_processing']}")
            continue
        print('Invalid choice.')


def role_auditor_menu():
    while True:
        print('\n--- AUDITOR MENU ---')
        print('1) List processed transactions (hashes only)')
        print('2) Verify signatures on processed transactions')
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
                eg = CUSTOMER_KEYS.get(customer)
                if not eg:
                    print(f"ID {t['id']}: No public key for customer {customer}.")
                    continue
                received_hash_bytes = bytes.fromhex(t['received_hash_hex'])
                sig_ok = eg.verify(received_hash_bytes, t['signature'])
                print(f"ID {t['id']}: signature_valid={sig_ok} (verified using customer's public key).")
            continue
        print('Invalid choice.')

# -------------------------------
# Initialization & Main Menu
# -------------------------------

def initialize_demo():
    # Create a merchant Rabin keypair and a sample customer ElGamal keys
    create_rabin_for_merchant('Merchant', bits=512)
    # Customer keys are created lazily when customer uses menu


def main_menu():
    initialize_demo()
    print('\nWelcome to the Rabin+ElGamal Transaction System (demo)')
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
            role_merchant_menu('Merchant')
        elif choice == '3':
            role_auditor_menu()
        else:
            print('Invalid choice.')

if __name__ == '__main__':
    main_menu()
