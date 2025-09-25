import random

# Step 1: Define the plaintext message
pt = "Confidential Data"

# Step 2: Utility functions to convert strings <-> integers
def string_to_int(text):
    # Converts text to integer using big-endian byte encoding
    return int.from_bytes(text.encode(), 'big')

def int_to_string(num):
    # Converts integer back to text
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode()

# Step 3: ElGamal parameters
# Prime modulus (p) and generator (g)
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

# Step 4: Generate private key x (teacher may give this)
x = random.randint(2, p - 2)  # Private key (should be kept secret)
h = pow(g, x, p)               # Compute public key h = g^x mod p

# Step 5: Print parameters (for clarity; include teacher's given values in comments if provided)
print(f"Plaintext: {pt}")
print(f"Prime p: {hex(p)}  # Teacher's value if given")
print(f"Generator g: {g}  # Teacher's value if given")
print(f"Private key x: {hex(x)}  # Teacher's value if given")
print(f"Public key h: {hex(h)}  # Computed from g^x mod p")

# Step 6: Convert message to integer for ElGamal
msg_int = string_to_int(pt)
print(f"Message as integer: {hex(msg_int)}")

# Step 7: Encryption
k = random.randint(2, p - 2)  # Random ephemeral key (teacher may specify)
c1 = pow(g, k, p)             # c1 = g^k mod p
c2 = (msg_int * pow(h, k, p)) % p  # c2 = m * h^k mod p

print(f"\nENCRYPTION")
print(f"Random k: {hex(k)}  # Teacher's value if provided")
print(f"c1 (hex): {hex(c1)}")
print(f"c2 (hex): {hex(c2)}")

# Step 8: Decryption
s = pow(c1, x, p)            # Shared secret s = c1^x mod p
s_inv = pow(s, p - 2, p)     # Modular inverse of s using Fermat's little theorem
decrypted_int = (c2 * s_inv) % p
mes = int_to_string(decrypted_int)

print(f"\nDECRYPTION")
print(f"Shared secret s: {hex(s)}")
print(f"Modular inverse s_inv: {hex(s_inv)}")
print(f"Decrypted integer: {hex(decrypted_int)}")
print(f"Decrypted message: {mes}")

# Step 9: Verification
print(f"\nVERIFICATION")
print(f"Original == Decrypted: {pt == mes}")
