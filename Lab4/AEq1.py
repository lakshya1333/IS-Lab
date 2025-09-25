# Question 1
# DigiRights Inc. is a leading provider of digital content, including e-books, movies, and
# music. The company has implemented a secure digital rights management (DRM)
# system using the ElGamal cryptosystem to protect its valuable digital assets.
# Implement a Python-based centralized key management and access control service that
# can:
# • Key Generation: Generate a master public-private key pair using the ElGamal
# cryptosystem. The key size should be configurable (e.g., 2048 bits).
# • Content Encryption: Provide an API for content creators to upload their digital content
# and have it encrypted using the master public key.
# • Key Distribution: Manage the distribution of the master private key to authorized
# customers, allowing them to decrypt the content.
# • Access Control: Implement flexible access control mechanisms, such as:
#  Granting limited-time access to customers for specific content
#  Revoking access to customers for specific content
#  Allowing content creators to manage access to their own content
# • Key Revocation: Implement a process to revoke the master private key in case of a
# security breach or other emergency.
# • Key Renewal: Automatically renew the master public-private key pair at regular
# intervals (e.g., every 24 months) to maintain the security of the DRM system.
# • Secure Storage: Securely store the master private key, ensuring that it is not accessible
# to unauthorized parties.
# • Auditing and Logging: Maintain detailed logs of all key management and access
# control operations to enable auditing and troubleshooting.



# ===============================
# DigiRights Inc. DRM System (ElGamal)
# ===============================

from Crypto.Util import number
from datetime import datetime, timedelta, timezone
import secrets

# -------------------------------
# Utility functions
# -------------------------------
def now_utc():
    """Return current UTC time."""
    return datetime.now(timezone.utc)

# -------------------------------
# ElGamal Key Management & DRM Service
# -------------------------------
class DRMSystem:
    """
    DRM System using ElGamal:
    - Generates master key pair
    - Encrypts digital content
    - Controls customer access
    - Manages key revocation/renewal
    - Provides auditing/logging
    """
    def __init__(self, key_bits=2048):
        self.key_bits = key_bits              # ElGamal key size
        self.master_key = None                # Stores master key pair
        self.content_store = {}               # Stores encrypted content
        self.access_control = {}              # Tracks customer access
        self.logs = []                        # Audit logs

    # -------------------------------
    # Logging function
    # -------------------------------
    def log(self, message):
        """Log messages with timestamp for auditing."""
        timestamp = now_utc().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp} - {message}"
        self.logs.append(log_entry)
        print(log_entry)

    # -------------------------------
    # Key Generation
    # -------------------------------
    def generate_master_key(self):
        """Generate ElGamal master public/private key pair."""
        # Large prime p
        p = number.getPrime(self.key_bits)
        g = 2  # Generator
        x = secrets.randbelow(p - 2) + 1  # Private key x
        h = pow(g, x, p)                   # Public key h = g^x mod p
        self.master_key = {"p": p, "g": g, "x": x, "h": h, "created": now_utc()}
        self.log(f"Master ElGamal key generated (p={p}, g={g}, h={h})")

    # -------------------------------
    # Content Encryption
    # -------------------------------
    def encrypt_content(self, content_id, plaintext):
        """
        Encrypt content using ElGamal public key (master key).
        Stores ciphertext in content_store.
        """
        if self.master_key is None:
            self.log("No master key available. Generate it first.")
            return None

        p, g, h = self.master_key["p"], self.master_key["g"], self.master_key["h"]
        m = int.from_bytes(plaintext.encode(), 'big')  # Convert string to integer

        # Choose random k
        k = secrets.randbelow(p - 2) + 1
        c1 = pow(g, k, p)
        c2 = (m * pow(h, k, p)) % p

        self.content_store[content_id] = {"c1": c1, "c2": c2}
        self.log(f"Content '{content_id}' encrypted and stored.")
        return {"c1": c1, "c2": c2}

    # -------------------------------
    # Content Decryption
    # -------------------------------
    def decrypt_content(self, content_id, customer_id):
        """
        Decrypt content for authorized customer using master private key.
        Checks access control before decryption.
        """
        if customer_id not in self.access_control.get(content_id, []):
            self.log(f"Access denied for {customer_id} on content '{content_id}'.")
            return None

        if content_id not in self.content_store:
            self.log(f"Content '{content_id}' not found.")
            return None

        c1, c2 = self.content_store[content_id]["c1"], self.content_store[content_id]["c2"]
        p, x = self.master_key["p"], self.master_key["x"]
        s = pow(c1, x, p)                    # Shared secret
        s_inv = pow(s, -1, p)                # Modular inverse
        m = (c2 * s_inv) % p
        plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
        self.log(f"Content '{content_id}' decrypted for customer '{customer_id}'.")
        return plaintext

    # -------------------------------
    # Access Control Management
    # -------------------------------
    def grant_access(self, content_id, customer_id):
        """Grant a customer access to a content item."""
        if content_id not in self.access_control:
            self.access_control[content_id] = []
        self.access_control[content_id].append(customer_id)
        self.log(f"Access granted to '{customer_id}' for content '{content_id}'.")

    def revoke_access(self, content_id, customer_id):
        """Revoke a customer's access to a content item."""
        if content_id in self.access_control and customer_id in self.access_control[content_id]:
            self.access_control[content_id].remove(customer_id)
            self.log(f"Access revoked for '{customer_id}' on content '{content_id}'.")

    # -------------------------------
    # Key Revocation & Renewal
    # -------------------------------
    def revoke_master_key(self):
        """Revoke the current master private key (emergency scenario)."""
        self.master_key = None
        self.log("Master private key revoked.")

    def renew_master_key(self):
        """Renew the master key pair for security (e.g., every 24 months)."""
        self.generate_master_key()
        self.log("Master key renewed.")

# ===============================
# Example Usage
# ===============================
if __name__ == "__main__":
    drm = DRMSystem(key_bits=512)  # Using smaller key for demo; exam can write 2048 bits
    drm.generate_master_key()

    # Upload and encrypt content
    drm.encrypt_content("ebook_001", "This is the content of e-book #1.")
    drm.encrypt_content("music_001", "Top secret music track.")

    # Grant customer access
    drm.grant_access("ebook_001", "customer_123")
    drm.grant_access("music_001", "customer_456")

    # Decrypt content
    print(drm.decrypt_content("ebook_001", "customer_123"))  # Allowed
    print(drm.decrypt_content("music_001", "customer_123"))  # Denied

    # Revoke access
    drm.revoke_access("ebook_001", "customer_123")
    print(drm.decrypt_content("ebook_001", "customer_123"))  # Denied

    # Renew master key
    drm.renew_master_key()
