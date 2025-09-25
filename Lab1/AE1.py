import string

# -------------------------------------------------------
# Ciphertext from Alice
# -------------------------------------------------------
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Uppercase English alphabet
alphabet = string.ascii_uppercase

# -------------------------------------------------------
# Function to decrypt additive (Caesar) cipher with given shift
# Formula: P = (C - key) mod 26
# -------------------------------------------------------
def decrypt(cipher, shift):
    result = ""
    for ch in cipher:
        if ch in alphabet:
            idx = alphabet.index(ch)                  # Get numerical index of character
            result += alphabet[(idx - shift) % 26]   # Subtract shift, wrap around modulo 26
        else:
            result += ch                              # Non-alphabetic characters remain unchanged
    return result

# -------------------------------------------------------
# Brute-force all possible keys (0-25)
# Highlight keys close to Alice's birthday (key ~ 13 ± 3)
# -------------------------------------------------------
for key in range(26):
    plaintext = decrypt(ciphertext, key)
    tag = " <--- close to birthday" if abs(key - 13) <= 3 else ""  # Mark likely keys
    print(f"Key {key:2d}: {plaintext}{tag}")
