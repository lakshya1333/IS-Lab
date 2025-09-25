# Question 2:
# HealthCare Inc., a leading healthcare provider, has implemented a secure patient data
# management system using the Rabin cryptosystem. The system allows authorized
# healthcare professionals to securely access and manage patient records across multiple
# hospitals and clinics within the organization. Implement a Python-based centralized key
# management service that can:
# • Key Generation: Generate public and private key pairs for each hospital and clinic
# using the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).
# • Key Distribution: Provide a secure API for hospitals and clinics to request and receive
# their public and private key pairs.
# • Key Revocation: Implement a process to revoke and update the keys of a hospital or
# clinic when necessary (e.g., when a facility is closed or compromised).
# • Key Renewal: Automatically renew the keys of all hospitals and clinics at regular
# intervals (e.g., every 12 months) to maintain the security of the patient data management
# system.
# • Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring
# that they are not accessible to unauthorized parties.
# • Auditing and Logging: Maintain detailed logs of all key management operations, such
# as key generation, distribution, revocation, and renewal, to enable auditing and
# compliance reporting.
# • Regulatory Compliance: Ensure that the key management service and its operations are
# 28
# compliant with relevant data privacy regulations (e.g., HIPAA).
# • Perform a trade-off analysis to compare the workings of Rabin and RSA.


# q2.py — tiny Rabin KMS (demo). Requires pycryptodome: pip install pycryptodome
# ===============================
# Rabin Key Management Service (KMS)
# ===============================

# Import libraries
from Crypto.Util import number               # Provides functions to generate primes
from datetime import datetime, timedelta, timezone  # For timestamping and expiration

# -------------------------------
# In-memory store for keys
# -------------------------------
# This dictionary stores keys for each hospital/clinic
# Key: facility ID, Value: dictionary containing Rabin keys, creation/expiry timestamps, revocation status
KS = {}

# -------------------------------
# Utility function: Current UTC time
# -------------------------------
def now_utc():
    """
    Returns the current UTC time.
    Used for creation, expiration, and logging.
    """
    return datetime.now(timezone.utc)

# -------------------------------
# Rabin Key Generation
# -------------------------------
def gen_rabin(bits=512):
    """
    Generate a Rabin key pair:
    - Public key: n = p * q
    - Private key: p, q (both ≡ 3 mod 4)
    - Key metadata: creation time, expiry, revocation status
    
    Args:
        bits: Total bit size of n. Each prime p and q is ~bits/2
    Returns:
        Dictionary containing n, p, q, creation timestamp, expiry, revoked status
    """
    # Generate p ≡ 3 mod 4
    while True:
        p = number.getPrime(bits//2)
        if p % 4 == 3:
            break

    # Generate q ≡ 3 mod 4, distinct from p
    while True:
        q = number.getPrime(bits//2)
        if q % 4 == 3 and q != p:
            break

    # Store metadata
    return {
        "n": p*q,                       # Public modulus
        "p": p,                          # Private prime
        "q": q,                          # Private prime
        "created": now_utc(),            # Timestamp when key generated
        "expires": now_utc() + timedelta(days=365),  # Key valid for 1 year
        "revoked": False                 # Status flag
    }

# -------------------------------
# Create keys for a hospital/clinic
# -------------------------------
def create(id_, bits=512):
    """
    Generate Rabin key pair for a facility and store in KS.
    """
    KS[id_] = gen_rabin(bits)
    print(f"[LOG] Created keys for {id_}")

# -------------------------------
# Retrieve public key
# -------------------------------
def public(id_):
    """
    Return public key information for a facility.
    Excludes private components.
    """
    r = KS.get(id_)
    if not r or r["revoked"]:
        return None  # Key does not exist or revoked
    return {
        "n": r["n"],                  # Public modulus
        "expires": r["expires"].isoformat()  # Expiration timestamp
    }

# -------------------------------
# Retrieve private key
# -------------------------------
def private(id_):
    """
    Return private key (p, q) for a facility.
    Only accessible if key is not revoked.
    """
    r = KS.get(id_)
    if not r or r["revoked"]:
        return None
    return {"p": r["p"], "q": r["q"]}

# -------------------------------
# Revoke keys
# -------------------------------
def revoke(id_):
    """
    Mark a facility's key as revoked.
    Revoked keys cannot be used for encryption or decryption.
    """
    if id_ in KS:
        KS[id_]["revoked"] = True
        print(f"[LOG] Revoked {id_}")

# -------------------------------
# Renew keys
# -------------------------------
def renew(id_, bits=512):
    """
    Generate a new key pair for a facility, replacing the old key.
    Resets creation and expiration timestamps.
    """
    if id_ in KS:
        KS[id_] = gen_rabin(bits)
        print(f"[LOG] Renewed keys for {id_}")

# ===============================
# Example usage
# ===============================
if __name__ == "__main__":
    # Step 1: Create keys for a hospital
    create("HospitalA")

    # Step 2: Access public and private keys
    print("Public:", public("HospitalA"))
    print("Private:", private("HospitalA"))

    # Step 3: Revoke keys when hospital is decommissioned or compromised
    revoke("HospitalA")
    print("After revocation -> Public:", public("HospitalA"))

    # Step 4: Renew keys for continued secure operation
    renew("HospitalA")
    print("After renewal -> Public:", public("HospitalA"))
