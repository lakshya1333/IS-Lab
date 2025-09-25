# 6. Use a brute-force attack to decipher the following message. Assume that you know it is
# an affine cipher and that the plaintext "ab" is enciphered to "GL":
# XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS


import string

# -------------------------------------------------------
# Ciphertext and known plaintext-ciphertext pair
# -------------------------------------------------------
cipher = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
known_pt = "ab"   # first two letters of plaintext
known_ct = "GL"   # corresponding ciphertext letters

# Alphabet & modulus for affine cipher
alpha = string.ascii_lowercase
m = 26

# -------------------------------------------------------
# Helper functions
# -------------------------------------------------------
def gcd(a, b):
    """Compute greatest common divisor"""
    while b:
        a, b = b, a % b
    return a

def mod_inv(a, m):
    """Find modular inverse of a mod m (brute-force)"""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No inverse exists")

def idx(c):
    """Convert character to index 0-25"""
    return alpha.index(c.lower())

def chr_i(i):
    """Convert index 0-25 back to character"""
    return alpha[i % m]

def affine_decrypt(ct, a, b):
    """Decrypt full ciphertext using affine keys a, b"""
    a_inv = mod_inv(a, m)  # Modular inverse of multiplicative key
    pt = ""
    for ch in ct:
        if ch.isalpha():
            y = idx(ch)
            x = (a_inv * (y - b)) % m
            pt += chr_i(x)
        else:
            pt += ch
    return pt

# -------------------------------------------------------
# Brute-force search for affine keys using known-plaintext
# -------------------------------------------------------
valid_keys = []

# Loop over all possible 'a' (must be coprime with 26)
for a in range(1, m):
    if gcd(a, m) != 1:
        continue
    # Loop over all possible 'b'
    for b in range(m):
        # Check if first two letters of known plaintext map correctly
        c0 = (a * idx(known_pt[0]) + b) % m
        c1 = (a * idx(known_pt[1]) + b) % m
        if chr_i(c0).upper() == known_ct[0] and chr_i(c1).upper() == known_ct[1]:
            valid_keys.append((a, b))

# -------------------------------------------------------
# Decrypt ciphertext using the found key
# -------------------------------------------------------
if not valid_keys:
    print("No valid key found")
else:
    a, b = valid_keys[0]                  # Take first valid key
    plaintext = affine_decrypt(cipher, a, b)
    print(f"Found key: a = {a}, b = {b}")
    print("Decrypted plaintext:", plaintext)
