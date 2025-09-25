import string

# -------------------------------------------------------
# Hill Cipher Encryption (2x2 key matrix version)
# Formula: C = K * P (mod 26)
# - P = plaintext vector of length 2
# - K = 2x2 key matrix
# - C = ciphertext vector of length 2
# -------------------------------------------------------
def hill_encrypt(msg, K):
    # 1. Preprocess plaintext
    msg = msg.replace(" ", "").upper()  # Remove spaces, convert to uppercase
    if len(msg) % 2 == 1:               # If odd length, pad with "X"
        msg += "X"

    # 2. Build lookup tables: letter → number, number → letter
    alphabet = {ch: i for i, ch in enumerate(string.ascii_uppercase)}
    rev = {i: ch for ch, i in alphabet.items()}

    # 3. Encrypt two letters (digraph) at a time
    ct = ""
    for i in range(0, len(msg), 2):
        # Take two plaintext characters → convert to numbers
        p1, p2 = alphabet[msg[i]], alphabet[msg[i+1]]

        # Multiply vector [p1, p2] with key matrix K (mod 26)
        c1 = (K[0][0] * p1 + K[0][1] * p2) % 26
        c2 = (K[1][0] * p1 + K[1][1] * p2) % 26

        # Convert back to letters
        ct += rev[c1] + rev[c2]

    return ct


# -------------------------------------------------------
# Driver Code
# -------------------------------------------------------
if __name__ == "__main__":
    # Key matrix
    K = [[3, 3],
         [2, 7]]

    # Message
    msg = "We live in an insecure world"

    # Encrypt
    ciphertext = hill_encrypt(msg, K)

    print("Plaintext :", msg)
    print("Ciphertext:", ciphertext)
