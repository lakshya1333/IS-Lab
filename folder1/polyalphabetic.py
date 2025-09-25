# POLYALPHABETIC CIPHERS - Multiple substitution alphabets used throughout message

# ===========================
# Vigenere Cipher
# ===========================
# Uses repeating keyword to shift letters by different amounts
# Formula: C[i] = (P[i] + K[i mod keylen]) mod 26

def vigenere_encrypt(text, key):
    """
    Vigenere cipher encryption - uses repeating keyword for shifts
    Args: text (string), key (string keyword)
    Returns: encrypted string
    Each letter shifted by corresponding key letter: A=0, B=1, ..., Z=25
    """
    key = key.upper()  # Ensure key is uppercase
    return ''.join(
        chr((ord(c) - 65 + ord(key[i % len(key)]) - 65) % 26 + 65)  # Add key letter value to plaintext letter
        if c.isalpha() else c  # Only encrypt letters
        for i, c in enumerate(text.upper())  # i tracks position for key cycling
    )

def vigenere_decrypt(cipher, key):
    """
    Vigenere cipher decryption - subtracts repeating keyword shifts
    Args: cipher (string), key (string keyword)
    Returns: decrypted string
    """
    key = key.upper()
    return ''.join(
        chr((ord(c) - 65 - (ord(key[i % len(key)]) - 65)) % 26 + 65)  # Subtract key letter value
        if c.isalpha() else c
        for i, c in enumerate(cipher.upper())
    )

# ===========================
# Autokey Cipher
# ===========================
# Uses keyword + plaintext itself as the key stream
# More secure than Vigenere as key doesn't repeat

def autokey_encrypt(text, key):
    """
    Autokey cipher encryption - key is keyword + plaintext
    Args: text (string), key (string initial keyword)
    Returns: encrypted string
    Key stream: [keyword][plaintext] - extends infinitely without repetition
    """
    text, key_stream = text.upper(), (key.upper() + text.upper())  # Concatenate key + plaintext
    return ''.join(
        chr((ord(t) - 65 + ord(key_stream[i]) - 65) % 26 + 65)  # Use extended key stream
        for i, t in enumerate(text)
    )

def autokey_decrypt(cipher, key):
    """
    Autokey cipher decryption - rebuilds key stream using recovered plaintext
    Args: cipher (string), key (string initial keyword)
    Returns: decrypted string
    """
    cipher, res, key_stream = cipher.upper(), "", key.upper()  # Initialize with keyword
    for i, c in enumerate(cipher):
        # Decrypt current character using current key stream position
        p = (ord(c) - 65 - (ord(key_stream[i]) - 65)) % 26
        res += chr(p + 65)  # Add decrypted character to result
        key_stream += res[-1]  # Extend key stream with newly decrypted character
    return res

# ===========================
# Playfair Cipher
# ===========================
# Uses 5x5 matrix for digraph (pair) substitution
# Rules: Same row→move right, Same column→move down, Rectangle→swap columns

def playfair_key_matrix(key):
    """
    Creates 5x5 Playfair key matrix from keyword
    Args: key (string)
    Returns: 5x5 matrix (list of lists)
    J and I treated as same letter, duplicates removed
    """
    key = ''.join(dict.fromkeys(key.upper().replace("J", "I")))  # Remove duplicates, J→I
    # Fill matrix: keyword + remaining alphabet letters
    matrix = key + ''.join(c for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ" if c not in key)
    return [list(matrix[i:i+5]) for i in range(0, 25, 5)]  # Convert to 5x5 matrix

def playfair_find(matrix, char):
    """
    Finds row,column position of character in 5x5 matrix
    Args: matrix (5x5 list), char (single character)
    Returns: (row, column) tuple
    """
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char: 
                return r, c

def playfair_process(text):
    """
    Converts text into digraphs (pairs) for Playfair encryption
    Args: text (string)
    Returns: string of paired characters
    Rule: If same letters in pair, insert 'X' between them
    """
    text = text.upper().replace("J", "I")  # Standardize J→I
    res, i = "", 0
    while i < len(text):
        a, b = text[i], (text[i+1] if i+1 < len(text) else 'X')  # Get pair, pad with X if needed
        if a == b: 
            res += a + "X"; i += 1  # Same letters: insert X, advance by 1
        else: 
            res += a + b; i += 2    # Different letters: use pair, advance by 2
    return res

def playfair_encrypt(text, key):
    """
    Playfair cipher encryption using 5x5 matrix rules
    Args: text (string), key (string)
    Returns: encrypted string
    Rules: Same row→right, Same column→down, Rectangle→swap columns
    """
    M = playfair_key_matrix(key)  # Generate key matrix
    text = playfair_process(text)  # Convert to digraphs
    res = ""
    for i in range(0, len(text), 2):  # Process each pair
        a, b = text[i], text[i+1]
        r1, c1 = playfair_find(M, a); r2, c2 = playfair_find(M, b)  # Find positions
        
        if r1 == r2:  # Same row: move right (wrap around)
            res += M[r1][(c1+1)%5] + M[r2][(c2+1)%5]
        elif c1 == c2:  # Same column: move down (wrap around)
            res += M[(r1+1)%5][c1] + M[(r2+1)%5][c2]
        else:  # Rectangle: swap columns
            res += M[r1][c2] + M[r2][c1]
    return res

def playfair_decrypt(cipher, key):
    """
    Playfair cipher decryption - reverse of encryption rules
    Args: cipher (string), key (string)
    Returns: decrypted string
    Rules: Same row→left, Same column→up, Rectangle→swap columns
    """
    M = playfair_key_matrix(key)
    res = ""
    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i+1]
        r1, c1 = playfair_find(M, a); r2, c2 = playfair_find(M, b)
        
        if r1 == r2:  # Same row: move left (wrap around)
            res += M[r1][(c1-1)%5] + M[r2][(c2-1)%5]
        elif c1 == c2:  # Same column: move up (wrap around)
            res += M[(r1-1)%5][c1] + M[(r2-1)%5][c2]
        else:  # Rectangle: swap columns (same as encryption)
            res += M[r1][c2] + M[r2][c1]
    return res

# ===========================
# Hill Cipher
# ===========================
# Uses matrix multiplication for encryption: C = P × K (mod 26)
# Requires key matrix to be invertible (determinant coprime to 26)

import numpy as np

def mod_inv_matrix(matrix, mod=26):
    """
    Computes modular inverse of matrix for Hill cipher decryption
    Args: matrix (numpy array), mod (integer, default 26)
    Returns: inverse matrix mod 26
    Formula: K^-1 = det(K)^-1 × adj(K) (mod 26)
    """
    det = int(round(np.linalg.det(matrix)))  # Calculate determinant
    det_inv = pow(det % mod, -1, mod)  # Modular inverse of determinant
    # Adjugate matrix = determinant × inverse matrix
    adj = np.round(det * np.linalg.inv(matrix)).astype(int) % mod
    return (det_inv * adj) % mod  # Final inverse matrix

def hill_encrypt(text, key_matrix):
    """
    Hill cipher encryption using matrix multiplication
    Args: text (string), key_matrix (nxn numpy array)
    Returns: encrypted string
    Process: Split text into n-letter blocks, multiply each by key matrix
    """
    n = len(key_matrix)  # Matrix size determines block size
    text = text.upper().replace(" ", "")  # Remove spaces, convert to uppercase
    while len(text) % n != 0: 
        text += "X"  # Pad with X to make length multiple of n
    
    res = ""
    for i in range(0, len(text), n):  # Process each n-letter block
        # Convert letters to numbers (A=0, B=1, ..., Z=25)
        block = [ord(c) - 65 for c in text[i:i+n]]
        # Matrix multiplication: cipher_block = key_matrix × plaintext_block (mod 26)
        cipher_block = np.dot(key_matrix, block) % 26
        # Convert numbers back to letters
        res += ''.join(chr(int(c) + 65) for c in cipher_block)
    return res

def hill_decrypt(cipher, key_matrix):
    """
    Hill cipher decryption using inverse matrix
    Args: cipher (string), key_matrix (nxn numpy array)
    Returns: decrypted string
    Process: Use inverse key matrix for decryption
    """
    inv_matrix = mod_inv_matrix(key_matrix)  # Get inverse matrix
    n, res = len(key_matrix), ""
    
    for i in range(0, len(cipher), n):  # Process each n-letter block
        # Convert cipher letters to numbers
        block = [ord(c) - 65 for c in cipher[i:i+n]]
        # Matrix multiplication with inverse: plaintext = inverse_matrix × cipher_block (mod 26)
        plain_block = np.dot(inv_matrix, block) % 26
        # Convert back to letters
        res += ''.join(chr(int(c) + 65) for c in plain_block)
    return res

# USAGE EXAMPLES:
# Vigenere: vigenere_encrypt("HELLO", "KEY") → uses K,E,Y,K,E shifts
# Autokey: autokey_encrypt("HELLO", "KEY") → uses K,E,Y,H,E shifts  
# Playfair: playfair_encrypt("HELLO", "KEYWORD") → encrypts HE,LL,OX pairs
# Hill: hill_encrypt("HELLO", [[3,2],[5,7]]) → 2x2 matrix on HE,LL,OX blocks
