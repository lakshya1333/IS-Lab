# Question 1
# SecureCorp is a large enterprise with multiple subsidiaries and business units located
# across different geographical regions. As part of their digital transformation initiative,
# the IT team at SecureCorp has been tasked with building a secure and scalable
# communication system to enable seamless collaboration and information sharing
# between their various subsystems.
# The enterprise system consists of the following key subsystems:
# 1. Finance System (System A): Responsible for all financial record-keeping, accounting,
# and reporting.
# 2. HR System (System B): Manages employee data, payroll, and personnel related
# processes.
# 3. Supply Chain Management (System C): Coordinates the flow of goods, services, and
# information across the organization's supply chain
# These subsystems need to communicate securely and exchange critical documents, such
# financial reports, employee contracts, and procurement orders, to ensure the enterprise's
# overall efficiency.
# The IT team at SecureCorp has identified the following requirements for the secure
# communication and document signing solution:
# 1. Secure Communication: The subsystems must be able to establish secure
# communication channels using a combination of RSA encryption and Diffie-Hellman
# 27
# key exchange.
# 2. Key Management: SecureCorp requires a robust key management system to generate,
# distribute, and revoke keys as needed to maintain the security of the enterprise system.
# 3. Scalability: The solution must be designed to accommodate the addition of new
# subsystems in the future as SecureCorp continues to grow and expand its operations.
# Implement a Python program which incorporates the requirements


# Import necessary libraries
from Crypto.PublicKey import RSA          # For RSA key generation (optional for hybrid setup)
from Crypto.Cipher import AES             # AES for symmetric encryption of messages
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime   # Generate large primes for Diffie-Hellman
import time                               # For logging timestamps

# ===============================
# Define the secure communication system class
# ===============================
class SecureCommunicationSystem:
    """
    This class manages subsystems, generates keys, performs Diffie-Hellman key exchange,
    encrypts/decrypts messages using AES, and supports key revocation.
    """
    def __init__(self):
        self.subsystems = {}   # Dictionary to store each subsystem's data (keys, shared secrets)
        self.logs = []         # List to store system logs

    # -------------------------------
    # Utility function: Logging
    # -------------------------------
    def log(self, message):
        """
        Add a timestamped log entry and print it.
        """
        self.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        print(message)

    # -------------------------------
    # Create a subsystem
    # -------------------------------
    def create_system(self, subsystem_id):
        """
        Initialize a subsystem with a private value for Diffie-Hellman key exchange.
        """
        self.subsystems[subsystem_id] = {
            'shared_key': None,              # Initially no shared key
            'private': get_random_bytes(32)  # Random private bytes for DH
        }
        self.log(f"{subsystem_id} created.")

    # -------------------------------
    # Diffie-Hellman Key Exchange
    # -------------------------------
    def dh_key_exchange(self, sender_id, receiver_id):
        """
        Establish a shared secret key between two subsystems using Diffie-Hellman.
        """
        # Step 1: Generate a large prime (p) for modulo operations
        p = getPrime(2048)
        g = 2  # Generator/base

        # Step 2: Compute sender's public value
        a = int.from_bytes(self.subsystems[sender_id]['private'], 'big')  # Private key as int
        A = pow(g, a, p)  # Public key: g^a mod p

        # Step 3: Compute receiver's public value
        b = int.from_bytes(self.subsystems[receiver_id]['private'], 'big')
        B = pow(g, b, p)

        # Step 4: Each subsystem computes the shared secret
        shared_secret_sender = pow(B, a, p)
        shared_secret_receiver = pow(A, b, p)

        # Step 5: Verify both computed the same shared secret
        if shared_secret_sender == shared_secret_receiver:
            # Reduce key size to 16 bytes for AES
            shared_key = shared_secret_sender % (2 ** 128)
            self.subsystems[sender_id]['shared_key'] = shared_key
            self.subsystems[receiver_id]['shared_key'] = shared_key
            self.log(f"Shared key established between {sender_id} and {receiver_id}.")
        else:
            self.log("Failed to establish shared key.")

    # -------------------------------
    # Encrypt message
    # -------------------------------
    def encrypt_message(self, sender_id, receiver_id, message):
        """
        Encrypt a message from sender to receiver using AES with the shared key.
        """
        # Step 1: Ensure shared key exists
        if sender_id not in self.subsystems or self.subsystems[sender_id]['shared_key'] is None:
            self.log(f"No shared key found for {sender_id}.")
            return None

        # Step 2: Convert shared key to 16 bytes (AES key)
        shared_key = self.subsystems[receiver_id]['shared_key'].to_bytes(16, 'big')

        # Step 3: Create AES cipher object in EAX mode (provides authentication)
        cipher_aes = AES.new(shared_key, AES.MODE_EAX)

        # Step 4: Encrypt the message and compute authentication tag
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

        # Step 5: Return concatenated nonce + tag + ciphertext
        return cipher_aes.nonce + tag + ciphertext  

    # -------------------------------
    # Decrypt message
    # -------------------------------
    def decrypt_message(self, receiver_id, encrypted_message):
        """
        Decrypt a message received by a subsystem using AES with the shared key.
        """
        if receiver_id not in self.subsystems or self.subsystems[receiver_id]['shared_key'] is None:
            self.log(f"No shared key found for {receiver_id}.")
            return None

        # Step 1: Convert shared key to 16 bytes
        shared_key = self.subsystems[receiver_id]['shared_key'].to_bytes(16, 'big')

        # Step 2: Extract nonce, tag, and ciphertext from the encrypted message
        nonce = encrypted_message[:16]
        tag = encrypted_message[16:32]
        ciphertext = encrypted_message[32:]

        # Step 3: Create AES cipher with shared key and nonce
        cipher_aes = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)

        try:
            # Step 4: Decrypt and verify authentication tag
            original_message = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
            self.log(f"Message decrypted for {receiver_id}.")
            return original_message
        except ValueError:
            self.log("Decryption failed: MAC check failed.")
            return None

    # -------------------------------
    # Revoke keys
    # -------------------------------
    def revoke_key(self, subsystem_id):
        """
        Remove a subsystem's keys to revoke access.
        """
        if subsystem_id in self.subsystems:
            del self.subsystems[subsystem_id]
            self.log(f"Keys revoked for subsystem {subsystem_id}.")

# ===============================
# Example usage
# ===============================
secure_system = SecureCommunicationSystem()

# Step 1: Create subsystems
secure_system.create_system("Finance System")
secure_system.create_system("HR System")
secure_system.create_system("Supply Chain Management")

# Step 2: Establish shared keys between subsystems using DH
secure_system.dh_key_exchange("Finance System", "HR System")
secure_system.dh_key_exchange("Supply Chain Management", "HR System")
secure_system.dh_key_exchange("Supply Chain Management", "Finance System")

# Step 3: Encrypt a message from Finance to HR
encrypted_msg = secure_system.encrypt_message("Finance System", "HR System", 
                                              "Confidential financial report.")

# Step 4: Decrypt the message at HR
original_message = secure_system.decrypt_message("HR System", encrypted_msg)
if original_message:
    print(f"Decrypted Message: {original_message}")
else:
    print("Failed to decrypt the message.")

# Step 5: Revoke keys (if necessary)
secure_system.revoke_key("Finance System")
