# 1. Using DES and AES (128, 192, and 256 bits key).encrypt the five different messages
# using same key.
# a. Consider different modes of operation
# b. Plot the graph which shows execution time taken by each technique.
# c. Compare time taken by different modes of operation



import time
import matplotlib.pyplot as plt
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# -------------------------------------------------------
# Sample messages for encryption (different lengths)
# -------------------------------------------------------
messages = [
    b"Hello World!",  # short message
    b"Cryptography is fun.",  # medium
    b"Symmetric encryption test with DES and AES.",  # longer
    b"Data Security is crucial in modern communication.",
    b"Benchmarking encryption algorithms with Python!"
]

# -------------------------------------------------------
# Modes to test
# -------------------------------------------------------
# ECB: Electronic Codebook (simple, not secure for repeated blocks)
# CBC: Cipher Block Chaining (needs IV)
# CFB: Cipher Feedback (stream-like mode)
# OFB: Output Feedback (stream-like mode)
# CTR: Counter mode (stream mode, uses nonce instead of IV)
modes = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB,
    "OFB": AES.MODE_OFB,
    "CTR": AES.MODE_CTR
}

results = {}  # Store execution times

# -------------------------------------------------------
# Benchmark function
# -------------------------------------------------------
def benchmark_cipher(cipher_name, key_size=None):
    times = {}
    
    # DES encryption
    if cipher_name == "DES":
        key = get_random_bytes(8)  # DES uses 8-byte key
        for mode_name, mode in modes.items():
            # DES CTR uses nonce instead of IV
            if mode == AES.MODE_CTR:
                cipher = DES.new(key, mode, nonce=b"0")
            elif mode == AES.MODE_ECB:
                cipher = DES.new(key, mode)
            else:
                iv = get_random_bytes(8)  # DES block size = 8 bytes
                cipher = DES.new(key, mode, iv=iv)

            # Measure execution time for encrypting all messages
            start = time.time()
            for msg in messages:
                padded_msg = pad(msg, 8)  # pad to multiple of 8 bytes
                cipher.encrypt(padded_msg)
            times[mode_name] = time.time() - start

    # AES encryption
    else:
        key = get_random_bytes(key_size // 8)  # 16, 24, or 32 bytes for AES-128/192/256
        block_size = 16  # AES block size
        for mode_name, mode in modes.items():
            if mode == AES.MODE_CTR:
                cipher = AES.new(key, mode, nonce=b"0")
            elif mode == AES.MODE_ECB:
                cipher = AES.new(key, mode)
            else:
                iv = get_random_bytes(block_size)
                cipher = AES.new(key, mode, iv=iv)

            start = time.time()
            for msg in messages:
                padded_msg = pad(msg, block_size)
                cipher.encrypt(padded_msg)
            times[mode_name] = time.time() - start

    results[f"{cipher_name}-{key_size if key_size else ''}"] = times

# -------------------------------------------------------
# Run benchmarks
# -------------------------------------------------------
benchmark_cipher("DES")
benchmark_cipher("AES", 128)
benchmark_cipher("AES", 192)
benchmark_cipher("AES", 256)

# -------------------------------------------------------
# Plot results
# -------------------------------------------------------
for algo, times in results.items():
    plt.plot(list(times.keys()), list(times.values()), marker='o', label=algo)

plt.title("DES vs AES (128,192,256) Execution Time in Different Modes")
plt.xlabel("Modes of Operation")
plt.ylabel("Execution Time (seconds)")
plt.legend()
plt.grid(True)
plt.show()

# -------------------------------------------------------
# Notes & Variations:
# -------------------------------------------------------
# 1. Modes of operation:
#    - ECB: simplest, insecure for repeated plaintext blocks
#    - CBC: requires IV, more secure
#    - CFB/OFB/CTR: stream-like modes, no padding needed for CTR
#
# 2. AES key sizes:
#    - 128, 192, 256 bits
#    - Larger key = stronger security, slightly slower
#
# 3. DES:
#    - Only 56-bit effective key, considered insecure today
#    - Block size 8 bytes vs AES 16 bytes
#
# 4. Message length:
#    - Execution time increases with message size
#
# 5. IV / Nonce handling:
#    - For CBC/OFB/CFB, use random IV per encryption
#    - For CTR, use nonce + counter
#
# 6. You can also test decryption time separately
# 7. Can benchmark using `time.perf_counter()` for higher precision
