# 1. With the ElGamal public key (p = 7919, g = 2, h = 6465) and the private key x =
# 2999, encrypt the message "Asymmetric Algorithms". Decrypt the resulting
# ciphertext to verify the original message. 


import random

# Step 1: Define the plaintext message
pt = "Asymmetric Algorithms"

# Step 2: Utility functions to convert text <-> integers
def string_to_int(text):
    """Convert string to integer using big-endian byte encoding"""
    return int.from_bytes(text.encode(), 'big')

def int_to_string(num):
    """Convert integer back to string"""
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode()

# Step 3: ElGamal parameters (given by teacher)
p = 7919           # Prime modulus
g = 2              # Generator
x = 2999           # Private key
h = 6465           # Public key h = g^x mod p (given)

# Step 4: Display parameters
print(f"Plaintext: {pt}")
print(f"Prime p: {p}")
print(f"Generator g: {g}")
print(f"Private key x: {x}")
print(f"Public key h: {h}")

# Step 5: Convert plaintext to integer
msg_int = string_to_int(pt)
print(f"Message as integer: {msg_int}")

# Step 6: Encrypt the message
k = random.randint(2, p-2)  # Random ephemeral key (should be < p)
c1 = pow(g, k, p)            # c1 = g^k mod p
c2 = (msg_int * pow(h, k, p)) % p  # c2 = m * h^k mod p

print("\nENCRYPTION")
print(f"Random ephemeral key k: {k}")
print(f"Ciphertext c1: {c1}")
print(f"Ciphertext c2: {c2}")

# Step 7: Decrypt the message
s = pow(c1, x, p)               # Shared secret s = c1^x mod p
s_inv = pow(s, p-2, p)          # Modular inverse of s using Fermat's little theorem
decrypted_int = (c2 * s_inv) % p
mes = int_to_string(decrypted_int)

print("\nDECRYPTION")
print(f"Shared secret s: {s}")
print(f"Modular inverse s_inv: {s_inv}")
print(f"Decrypted integer: {decrypted_int}")
print(f"Decrypted message: {mes}")

# Step 8: Verify correctness
print("\nVERIFICATION")
print(f"Original == Decrypted: {pt == mes}")
