# 5. John is reading a mystery book involving cryptography. In one part of the book, the
# author gives a ciphertext "CIW" and two paragraphs later the author tells the reader that
# this is a shift cipher and the plaintext is "yes". In the next chapter, the hero found a tablet
# in a cave with "XVIEWYWI" engraved on it. John immediately found the actual meaning
# of the ciphertext. Identify the type of attack and plaintext.


import string

# -------------------------------------------------------
# Helper function: derive Caesar shift from known ciphertext and plaintext
# Formula: k = (C - P) mod 26
# -------------------------------------------------------
def shift_value(cipher_char, plain_char):
    return (ord(cipher_char) - ord(plain_char)) % 26

# -------------------------------------------------------
# Decrypt Caesar cipher with given shift k
# Formula: P = (C - k) mod 26
# -------------------------------------------------------
def caesar_decrypt(ciphertext, k):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            # Convert letter to 0-25, subtract key, mod 26, convert back
            p = (ord(c) - ord('A') - k) % 26
            plaintext += chr(p + ord('A'))
        else:
            plaintext += c  # Keep non-alphabet characters as-is
    return plaintext

# -------------------------------------------------------
# Driver Code
# -------------------------------------------------------
if __name__ == "__main__":
    # Step 1: Known-plaintext example from the book
    plaintext_sample = "YES"
    ciphertext_sample = "CIW"

    # Step 2: Derive the shift key using the first letters of known plaintext/ciphertext
    k = shift_value(ciphertext_sample[0], plaintext_sample[0])
    print("Derived Caesar shift:", k)

    # Step 3: Use the same key to decrypt the cave text
    cave_text = "XVIEWYWI"
    decoded = caesar_decrypt(cave_text, k)

    print("Ciphertext :", cave_text)
    print("Plaintext  :", decoded)
