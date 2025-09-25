# a) The type of attack is a known-plaintext attack.
#    Eve has both the plaintext "abcdefghi" and its corresponding
#    ciphertext "CABDEHFGL". This is a specific type of
#    known-plaintext attack where the plaintext is very simple and
#    often called a 'crib'.

# b) The size of the permutation key is 3.

#    We can deduce this by observing the block transformations.
#    The plaintext "abcdefghi" is likely divided into blocks of 3.
#    Plaintext blocks: "abc", "def", "ghi"
#    Ciphertext blocks: "CAB", "DEH", "FGL"

#    'abc' -> 'CAB'
#    'a' (pos 0) moves to pos 1
#    'b' (pos 1) moves to pos 2
#    'c' (pos 2) moves to pos 0
#    The permutation is (2, 0, 1)

# c) Vigenère Cipher with keyword "HEALTH"
def vigenere_encrypt(message, keyword):
    """
    Encrypts a message using the Vigenere cipher.
    """
    encrypted_message = ""
    # Remove spaces and convert to uppercase for consistency
    message = message.replace(" ", "").upper()
    keyword = keyword.upper()
    key_length = len(keyword)

    for i, char in enumerate(message):
        # Find the numerical value of the plaintext character (A=0, B=1, ...)
        plaintext_val = ord(char) - ord('A')
        # Find the numerical value of the corresponding keyword character
        keyword_val = ord(keyword[i % key_length]) - ord('A')
        # Apply the Vigenere formula: (P + K) mod 26
        encrypted_val = (plaintext_val + keyword_val) % 26
        # Convert the numerical value back to a character
        encrypted_char = chr(encrypted_val + ord('A'))
        encrypted_message += encrypted_char

    return encrypted_message

message = "Life is full of surprises"
keyword = "HEALTH"
ciphertext = vigenere_encrypt(message, keyword)

print(f"Original message: {message}")
print(f"Encrypted message: {ciphertext}")
# Expected output: SMFPBZJUWEVJSFKWVFDXZ