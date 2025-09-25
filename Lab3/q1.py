from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

pt = "Asymmetric Encryption"

key = RSA.generate(2048)
n = key.n
e = key.e
d = key.d

print(f"Plaintext: {pt}")
print(f"RSA key size: 2048 bits")
print(f"Public key (n): {hex(n)}")
print(f"Public exponent (e): {e}")
print(f"Private exponent (d): {hex(d)}")

public_key = RSA.construct((n, e))
private_key = RSA.construct((n, e, d))

cipher_encrypt = PKCS1_OAEP.new(public_key)
cipher_decrypt = PKCS1_OAEP.new(private_key)

ct = cipher_encrypt.encrypt(pt.encode())
print(f"Ciphertext (hex): {ct.hex()}")
print(f"Ciphertext length: {len(ct)} bytes")

mes = cipher_decrypt.decrypt(ct).decode()
print(f"Decrypted message: {mes}")

print(f"Original == Decrypted: {pt == mes}")





# # Simple RSA Example in Python
# # Encrypt and decrypt the message "Asymmetric Encryption"
# # Using fixed numbers for demonstration

# # Step 1: Define the public and private keys
# # Public key (n, e) and private key (n, d)
# n = 3233          # modulus (product of two primes, e.g., 61*53)
# e = 17            # public exponent
# d = 413           # private exponent (computed from e, p, q)

# # Step 2: Define the message
# message = "Asymmetric Encryption"

# # Step 3: Convert message to a number (simple ASCII conversion)
# def text_to_numbers(text):
#     return [ord(char) for char in text]

# def numbers_to_text(numbers):
#     return ''.join([chr(num) for num in numbers])

# message_numbers = text_to_numbers(message)
# print("Message as numbers:", message_numbers)

# # Step 4: Encrypt the message using the public key
# def encrypt(numbers, e, n):
#     # RSA encryption: c = m^e mod n
#     return [pow(num, e, n) for num in numbers]

# ciphertext = encrypt(message_numbers, e, n)
# print("Ciphertext:", ciphertext)

# # Step 5: Decrypt the message using the private key
# def decrypt(ciphertext, d, n):
#     # RSA decryption: m = c^d mod n
#     return [pow(num, d, n) for num in ciphertext]

# decrypted_numbers = decrypt(ciphertext, d, n)
# print("Decrypted numbers:", decrypted_numbers)

# # Step 6: Convert decrypted numbers back to text
# decrypted_message = numbers_to_text(decrypted_numbers)
# print("Decrypted message:", decrypted_message)




# #!/usr/bin/env python3
# """
# Textbook RSA demo (educational).
# Generates RSA keys (two probable primes), encrypts a UTF-8 message by converting
# it to an integer, then decrypts and verifies.

# WARNING: This is for learning only. No padding (e.g. OAEP) is used. Do NOT use
# this for real security.
# """
# import random
# import math

# # ----------------------------
# # Miller-Rabin primality test
# # ----------------------------
# def is_probable_prime(n, k=10):
#     """Return True if n is probably prime (Miller-Rabin with k rounds)."""
#     if n < 2:
#         return False
#     # Quick checks with small primes
#     small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
#     for p in small_primes:
#         if n % p == 0:
#             return n == p
#     # write n-1 as d * 2^s
#     s = 0
#     d = n - 1
#     while d % 2 == 0:
#         d //= 2
#         s += 1
#     # witness loop
#     for _ in range(k):
#         a = random.randrange(2, n - 1)
#         x = pow(a, d, n)
#         if x == 1 or x == n - 1:
#             continue
#         composite = True
#         for _ in range(s - 1):
#             x = pow(x, 2, n)
#             if x == n - 1:
#                 composite = False
#                 break
#         if composite:
#             return False
#     return True

# def generate_prime(bits):
#     """Generate a probable prime of 'bits' bits."""
#     while True:
#         # create an odd candidate with top bit set (to ensure bit length)
#         candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
#         if is_probable_prime(candidate):
#             return candidate

# # ----------------------------
# # Extended GCD & modular inverse
# # ----------------------------
# def egcd(a, b):
#     if b == 0:
#         return (a, 1, 0)
#     g, x1, y1 = egcd(b, a % b)
#     return (g, y1, x1 - (a // b) * y1)

# def modinv(a, m):
#     g, x, _ = egcd(a, m)
#     if g != 1:
#         raise ValueError("Modular inverse does not exist")
#     return x % m

# # ----------------------------
# # RSA functions
# # ----------------------------
# def generate_rsa_keys(bits_per_prime=512, e=65537):
#     """Generate RSA key pair. Returns (n, e, d, p, q)."""
#     p = generate_prime(bits_per_prime)
#     q = generate_prime(bits_per_prime)
#     while q == p:
#         q = generate_prime(bits_per_prime)

#     n = p * q
#     phi = (p - 1) * (q - 1)

#     # ensure e is coprime with phi
#     if math.gcd(e, phi) != 1:
#         # find a small odd e that works
#         for cand in range(3, 100000, 2):
#             if math.gcd(cand, phi) == 1:
#                 e = cand
#                 break

#     d = modinv(e, phi)
#     return n, e, d, p, q

# def encrypt_int(m_int, e, n):
#     return pow(m_int, e, n)

# def decrypt_int(c_int, d, n):
#     return pow(c_int, d, n)

# # ----------------------------
# # Utility: message <-> integer
# # ----------------------------
# def message_to_int(message: str) -> (int, int):
#     b = message.encode('utf-8')
#     return int.from_bytes(b, byteorder='big'), len(b)

# def int_to_message(m_int: int, length_bytes: int) -> str:
#     b = m_int.to_bytes(length_bytes, byteorder='big')
#     return b.decode('utf-8')

# # ----------------------------
# # Demo / main
# # ----------------------------
# def main():
#     message = "Asymmetric Encryption"
#     bits = 512  # each prime size; resulting n is ~1024 bits

#     print("Generating RSA keys (this may take a moment)...")
#     n, e, d, p, q = generate_rsa_keys(bits_per_prime=bits, e=65537)

#     print(f"Generated keys. n bit-length = {n.bit_length()}, e = {e}")

#     # convert message to integer
#     m_int, m_len = message_to_int(message)
#     # ensure message integer < n
#     if m_int >= n:
#         raise ValueError("Message integer >= modulus n. Use larger primes or shorter message.")

#     # encrypt
#     c_int = encrypt_int(m_int, e, n)
#     # decrypt
#     m2_int = decrypt_int(c_int, d, n)
#     # convert back to string
#     message_decrypted = int_to_message(m2_int, m_len)

#     print("\n--- Results ---")
#     print("Original message:", message)
#     print("Decrypted message:", message_decrypted)
#     print("Verification: decrypted == original ->", message_decrypted == message)

#     # optionally print numeric keys (huge integers)
#     print("\nPublic key (n, e):")
#     print("n =", n)
#     print("e =", e)
#     print("\nPrivate key (n, d):")
#     print("d =", d)
#     print("\nPrimes p, q (kept secret in real use):")
#     print("p =", p)
#     print("q =", q)

# if __name__ == "__main__":
#     main()
