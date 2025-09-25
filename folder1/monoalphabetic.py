# MONOALPHABETIC CIPHERS - Single substitution alphabet for entire message

# ===========================
# Additive (Caesar) Cipher
# ===========================
# Formula: Encryption = (P + k) mod 26, Decryption = (C - k) mod 26
# Where P = plaintext position (A=0, B=1, ..., Z=25), k = key shift value

def caesar_encrypt(text, key):
    """
    Caesar cipher encryption - shifts each letter by 'key' positions in alphabet
    Args: text (string), key (integer 0-25)
    Returns: encrypted string with same case and non-alphabetic chars unchanged
    """
    return ''.join(
        chr((ord(c) - 65 + key) % 26 + 65)  # Convert to 0-25, add key, mod 26, convert back to ASCII
        if c.isalpha() else c  # Only encrypt alphabetic characters
        for c in text.upper()  # Convert to uppercase for consistency
    )

def caesar_decrypt(cipher, key):
    """
    Caesar cipher decryption - shifts each letter backward by 'key' positions
    Args: cipher (string), key (integer 0-25)
    Returns: decrypted string
    """
    return ''.join(
        chr((ord(c) - 65 - key) % 26 + 65)  # Convert to 0-25, subtract key, mod 26, convert back
        if c.isalpha() else c  # Only decrypt alphabetic characters
        for c in cipher.upper()
    )

# ===========================
# Multiplicative Cipher
# ===========================
# Formula: Encryption = (P * k) mod 26, Decryption = (C * k^-1) mod 26
# Constraint: k must be coprime to 26 (gcd(k,26) = 1), valid keys: 1,3,5,7,9,11,15,17,19,21,23,25

def multiplicative_encrypt(text, key):
    """
    Multiplicative cipher - multiplies each letter position by key
    Args: text (string), key (integer coprime to 26)
    Returns: encrypted string
    Note: Key must be coprime to 26 for decryption to work
    """
    return ''.join(
        chr(((ord(c) - 65) * key) % 26 + 65)  # (letter_position * key) mod 26
        if c.isalpha() else c
        for c in text.upper()
    )

def multiplicative_decrypt(cipher, key):
    """
    Multiplicative cipher decryption using modular inverse
    Args: cipher (string), key (integer coprime to 26)
    Returns: decrypted string
    """
    inv = pow(key, -1, 26)  # Find modular inverse of key mod 26 (Python 3.8+)
    return ''.join(
        chr(((ord(c) - 65) * inv) % 26 + 65)  # (letter_position * key_inverse) mod 26
        if c.isalpha() else c
        for c in cipher.upper()
    )

# ===========================
# Affine Cipher (Multiplicative + Additive)
# ===========================
# Formula: Encryption = (a*P + b) mod 26, Decryption = a^-1*(C - b) mod 26
# Combines multiplicative (a) and additive (b) transformations

def affine_encrypt(text, a, b):
    """
    Affine cipher encryption - combines multiplication and addition
    Args: text (string), a (multiplicative key, coprime to 26), b (additive key, 0-25)
    Returns: encrypted string
    Formula: (a * letter_position + b) mod 26
    """
    return ''.join(
        chr(((a * (ord(c) - 65) + b) % 26) + 65)  # Apply affine transformation
        if c.isalpha() else c
        for c in text.upper()
    )

def affine_decrypt(cipher, a, b):
    """
    Affine cipher decryption using modular inverse
    Args: cipher (string), a (multiplicative key), b (additive key)
    Returns: decrypted string
    Formula: a^-1 * (letter_position - b) mod 26
    """
    inv = pow(a, -1, 26)  # Modular inverse of 'a' mod 26
    return ''.join(
        chr((inv * ((ord(c) - 65) - b)) % 26 + 65)  # Reverse affine transformation
        if c.isalpha() else c
        for c in cipher.upper()
    )

# USAGE EXAMPLES:
# Caesar: caesar_encrypt("HELLO", 3) -> "KHOOR"
# Multiplicative: multiplicative_encrypt("HELLO", 5) -> "DAZZK"  
# Affine: affine_encrypt("HELLO", 5, 8) -> "LYBBK"
