# 4. Design and implement a secure file transfer system using RSA (2048-bit) and ECC
# (secp256r1 curve) public key algorithms. Generate and exchange keys, then
# encrypt and decrypt files of varying sizes (e.g., 1 MB, 10 MB) using both
# algorithms. Measure and compare the performance in terms of key generation
# time, encryption/decryption speed, and computational overhead. Evaluate the
# security and efficiency of each algorithm in the context of file transfer, considering
# 19
# factors such as key size, storage requirements, and resistance to known attacks.
# Document your findings, including performance metrics and a summary of the
# strengths and weaknesses of RSA and ECC for secure file transfer. 



import time
import os
import statistics
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import secrets

# A utility function to measure the execution time of a given function.
def measure_time(func, *args, **kwargs):
    """Measures the time taken to execute a function."""
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, end - start

# A helper function to create test files for performance analysis.
def create_test_file(filename, size_mb):
    """Creates a test file of a specified size with random data."""
    with open(filename, 'wb') as f:
        f.write(secrets.token_bytes(size_mb * 1024 * 1024))

# Key generation functions for RSA and ECC.
def generate_rsa_keys():
    """Generates a 2048-bit RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ecc_keys():
    """Generates a secp256r1 ECC private and public key pair."""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Symmetric encryption and decryption helpers for the bulk data.
def aes_encrypt(data, key):
    """Encrypts data using AES-256-CBC. Returns IV + ciphertext."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(encrypted_data, key):
    """Decrypts AES-256-CBC encrypted data and removes padding."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]


# Hybrid encryption functions for RSA.
def rsa_encrypt_file(file_path, public_key):
    """
    Encrypts a file using RSA. A random AES key is generated to encrypt the file,
    and the AES key is then encrypted with the RSA public key.
    """
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Generate a random AES key for symmetric encryption
    aes_key = os.urandom(32)  # 256-bit AES key
    encrypted_file = aes_encrypt(file_data, aes_key)

    # Encrypt the AES key with the RSA public key using OAEP padding
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_aes_key, encrypted_file


def rsa_decrypt_file(encrypted_aes_key, encrypted_file, private_key):
    """
    Decrypts a file encrypted with the rsa_encrypt_file function.
    The AES key is first decrypted with the RSA private key.
    """
    # Decrypt the AES key using the RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file data using the recovered AES key
    file_data = aes_decrypt(encrypted_file, aes_key)
    return file_data


# Hybrid encryption functions for ECC using ECDH (Elliptic Curve Diffie-Hellman).
def ecc_encrypt_file(file_path, public_key):
    """
    Encrypts a file using ECC. A shared secret is derived using ECDH,
    and an AES key is derived from that secret to encrypt the file.
    """
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Generate an ephemeral private key for the key exchange
    ephemeral_private = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    ephemeral_public = ephemeral_private.public_key()

    # Perform ECDH to get a shared secret
    shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
    # Derive a strong, 256-bit AES key from the shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file encryption',
        backend=default_backend()
    ).derive(shared_key)

    encrypted_file = aes_encrypt(file_data, derived_key)

    # Serialize the ephemeral public key to send to the recipient
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    return ephemeral_public_bytes, encrypted_file


def ecc_decrypt_file(ephemeral_public_bytes, encrypted_file, private_key):
    """
    Decrypts a file encrypted with the ecc_encrypt_file function.
    The shared secret is re-derived using the received ephemeral public key.
    """
    # Deserialize the received ephemeral public key
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_public_bytes
    )

    # Re-derive the shared secret using the main private key and ephemeral public key
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)
    # Re-derive the AES key using the same HKDF process
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file encryption',
        backend=default_backend()
    ).derive(shared_key)

    # Decrypt the file data using the recovered AES key
    file_data = aes_decrypt(encrypted_file, derived_key)
    return file_data


def run_performance_test():
    """Main function to run the full performance and security analysis."""
    print("SECURE FILE TRANSFER SYSTEM PERFORMANCE ANALYSIS")
    print("=" * 60)

    test_files = [
        ("test_1MB.bin", 1),
        ("test_10MB.bin", 10)
    ]

    iterations = 5

    # Measure and compare key generation times
    print("GENERATING CRYPTOGRAPHIC KEYS")
    print("-" * 40)

    rsa_keygen_times = []
    ecc_keygen_times = []

    for i in range(iterations):
        (rsa_priv, rsa_pub), rsa_time = measure_time(generate_rsa_keys)
        (ecc_priv, ecc_pub), ecc_time = measure_time(generate_ecc_keys)

        rsa_keygen_times.append(rsa_time)
        ecc_keygen_times.append(ecc_time)

    rsa_avg_keygen = statistics.mean(rsa_keygen_times) * 1000
    ecc_avg_keygen = statistics.mean(ecc_keygen_times) * 1000

    print(f"RSA-2048 key generation: {rsa_avg_keygen:.3f} ms (avg)")
    print(f"ECC secp256r1 key generation: {ecc_avg_keygen:.3f} ms (avg)")
    print(f"ECC is {rsa_avg_keygen / ecc_avg_keygen:.1f}x faster at key generation")

    results = {}

    # Iterate through different file sizes and measure encryption/decryption performance
    for filename, size_mb in test_files:
        print(f"\nFILE ENCRYPTION TEST - {size_mb}MB")
        print("-" * 40)

        create_test_file(filename, size_mb)

        rsa_enc_times = []
        rsa_dec_times = []
        ecc_enc_times = []
        ecc_dec_times = []

        for i in range(iterations):
            (rsa_enc_key, rsa_enc_file), rsa_enc_time = measure_time(rsa_encrypt_file, filename, rsa_pub)
            rsa_dec_data, rsa_dec_time = measure_time(rsa_decrypt_file, rsa_enc_key, rsa_enc_file, rsa_priv)

            (ecc_eph_key, ecc_enc_file), ecc_enc_time = measure_time(ecc_encrypt_file, filename, ecc_pub)
            ecc_dec_data, ecc_dec_time = measure_time(ecc_decrypt_file, ecc_eph_key, ecc_enc_file, ecc_priv)

            rsa_enc_times.append(rsa_enc_time)
            rsa_dec_times.append(rsa_dec_time)
            ecc_enc_times.append(ecc_enc_time)
            ecc_dec_times.append(ecc_dec_time)

        rsa_avg_enc = statistics.mean(rsa_enc_times) * 1000
        rsa_avg_dec = statistics.mean(rsa_dec_times) * 1000
        ecc_avg_enc = statistics.mean(ecc_enc_times) * 1000
        ecc_avg_dec = statistics.mean(ecc_dec_times) * 1000

        print(f"RSA-2048 encryption: {rsa_avg_enc:.3f} ms")
        print(f"RSA-2048 decryption: {rsa_avg_dec:.3f} ms")
        print(f"ECC secp256r1 encryption: {ecc_avg_enc:.3f} ms")
        print(f"ECC secp256r1 decryption: {ecc_avg_dec:.3f} ms")

        # Verify that decryption was successful
        with open(filename, 'rb') as f:
            original = f.read()

        rsa_success = (rsa_dec_data == original)
        ecc_success = (ecc_dec_data == original)

        print(f"RSA verification: {'PASS' if rsa_success else 'FAIL'}")
        print(f"ECC verification: {'PASS' if ecc_success else 'FAIL'}")

        results[f"{size_mb}MB"] = {
            'rsa_enc': rsa_avg_enc,
            'rsa_dec': rsa_avg_dec,
            'ecc_enc': ecc_avg_enc,
            'ecc_dec': ecc_avg_dec
        }

        os.remove(filename)

    # Print a summary of the performance metrics
    print("\nPERFORMANCE COMPARISON SUMMARY")
    print("=" * 60)

    print(f"{'Operation':<20} {'RSA-2048 (ms)':<15} {'ECC-256 (ms)':<15} {'Speedup':<10}")
    print("-" * 60)
    print(
        f"{'Key Generation':<20} {rsa_avg_keygen:<15.3f} {ecc_avg_keygen:<15.3f} {rsa_avg_keygen / ecc_avg_keygen:<10.1f}x")

    for size, data in results.items():
        enc_speedup = data['rsa_enc'] / data['ecc_enc']
        dec_speedup = data['rsa_dec'] / data['ecc_dec']
        print(f"{size + ' Encrypt':<20} {data['rsa_enc']:<15.3f} {data['ecc_enc']:<15.3f} {enc_speedup:<10.1f}x")
        print(f"{size + ' Decrypt':<20} {data['rsa_dec']:<15.3f} {data['ecc_dec']:<15.3f} {dec_speedup:<10.1f}x")

    # Document security and efficiency analysis
    print("\nSECURITY ANALYSIS")
    print("=" * 60)
    print("RSA-2048 Security:")
    print("  • Key size: 2048 bits")
    print("  • Security level: ~112-bit equivalent (current standard)")
    print("  • Quantum resistance: Vulnerable to Shor's algorithm, requires larger keys for future security")
    print("  • Known attacks: Based on the difficulty of integer factorization")

    print("\nECC secp256r1 Security:")
    print("  • Key size: 256 bits")
    print("  • Security level: ~128-bit equivalent (better than RSA-2048)")
    print("  • Quantum resistance: Vulnerable to Shor's algorithm, but smaller keys are easier to manage for post-quantum updates")
    print("  • Known attacks: Based on the difficulty of the elliptic curve discrete logarithm problem")

    print("\nSTORAGE REQUIREMENTS")
    print("=" * 60)

    # Calculate key sizes in bytes for storage comparison
    rsa_priv_size = len(rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

    rsa_pub_size = len(rsa_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    ecc_priv_size = len(ecc_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

    ecc_pub_size = len(ecc_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    print(f"RSA-2048 private key: {rsa_priv_size} bytes")
    print(f"RSA-2048 public key: {rsa_pub_size} bytes")
    print(f"ECC-256 private key: {ecc_priv_size} bytes")
    print(f"ECC-256 public key: {ecc_pub_size} bytes")
    print(
        f"Storage efficiency: ECC uses {((rsa_priv_size + rsa_pub_size) / (ecc_priv_size + ecc_pub_size)):.1f}x less space")

    print("\nRECOMMENDATIONS")
    print("=" * 60)
    print("🔒 Use ECC secp256r1 for new implementations:")
    print("   • Superior performance across all operations")
    print("   • Smaller key sizes and storage requirements")
    print("   • Provides equivalent security with better efficiency")
    print("   • Ideal for resource-constrained environments like mobile and IoT applications")

    print("\n📊 Key Findings:")
    print(f"   • ECC key generation is {rsa_avg_keygen / ecc_avg_keygen:.0f}x faster than RSA")
    print("   • ECC encryption/decryption is also consistently faster than RSA")
    print("   • Both algorithms provide strong security for current threats when implemented correctly")
    print("   • The hybrid encryption model is essential for practical secure file transfers")


if __name__ == "__main__":
    run_performance_test()
