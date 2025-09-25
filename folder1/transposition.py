# TRANSPOSITION CIPHERS - Rearrange letter positions without changing letters themselves

# ===========================
# Rail Fence Cipher (Zigzag Pattern)
# ===========================
# Writes message in zigzag pattern across multiple "rails" (rows)
# Then reads off each rail sequentially to form ciphertext

def rail_fence_encrypt(text, rails):
    """
    Rail fence encryption - writes text in zigzag pattern across rails
    Args: text (string), rails (integer - number of rows)
    Returns: encrypted string
    
    Example with 3 rails and "HELLO WORLD":
    H . . . O . . . R . .    Rail 0: H O R
    . E . L . . W . . L .    Rail 1: E L W L  
    . . L . . . . O . . D    Rail 2: L O D
    Result: "HORELWLLOD"
    """
    # Create 2D fence structure - fence[rail][position]
    fence = [['' for _ in text] for _ in range(rails)]
    row, step = 0, 1  # Start at top rail, moving down
    
    # Fill fence with zigzag pattern
    for i, c in enumerate(text):
        fence[row][i] = c  # Place character at current rail and position
        
        # Change direction at top and bottom rails
        if row == 0: 
            step = 1      # At top: start moving down
        elif row == rails - 1: 
            step = -1     # At bottom: start moving up
        row += step       # Move to next rail
    
    # Read fence row by row to create ciphertext
    return ''.join(c for row in fence for c in row if c)

def rail_fence_decrypt(cipher, rails):
    """
    Rail fence decryption - reconstructs zigzag pattern then reads in order
    Args: cipher (string), rails (integer)
    Returns: decrypted string
    """
    # Create fence and mark positions that will be filled
    fence = [['' for _ in cipher] for _ in range(rails)]
    row, step = 0, 1
    
    # First pass: mark positions with '*' following zigzag pattern
    for i in range(len(cipher)):
        fence[row][i] = '*'  # Mark this position as used
        if row == 0: 
            step = 1
        elif row == rails - 1: 
            step = -1
        row += step
    
    # Second pass: fill marked positions with cipher characters row by row
    idx = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if fence[r][c] == '*':
                fence[r][c] = cipher[idx]
                idx += 1
    
    # Third pass: read fence following zigzag pattern to get plaintext
    res, row, step = "", 0, 1
    for i in range(len(cipher)):
        res += fence[row][i]  # Read character at current position
        if row == 0: 
            step = 1
        elif row == rails - 1: 
            step = -1
        row += step
    return res

# ===========================
# Columnar (Keyed) Transposition Cipher
# ===========================
# Arranges text in grid, then reads columns in alphabetical order of key

def columnar_encrypt(text, key):
    """
    Columnar transposition encryption using keyword
    Args: text (string), key (string keyword)
    Returns: encrypted string
    
    Example with key "ZEBRAS" and text "ATTACK AT DAWN":
    1. Arrange in grid under key:
       Z E B R A S
       A T T A C K
       A T D A W N
       X X X X X X  (padding)
    
    2. Sort columns by key alphabetically: A(4) B(2) E(1) R(3) S(5) Z(0)
    3. Read columns in sorted order: ACXX TTDX TTAX AAAX CKWX AKNN
    """
    n = len(key)  # Number of columns = key length
    # Pad text to fill complete rows
    text += 'X' * ((n - len(text) % n) % n)
    
    # Create matrix: split text into rows of length n
    matrix = [list(text[i:i+n]) for i in range(0, len(text), n)]
    
    # Determine column reading order: sort by key characters
    order = sorted(range(n), key=lambda k: key[k])
    
    # Read columns in sorted order
    return ''.join(matrix[r][c] for c in order for r in range(len(matrix)))

def columnar_decrypt(cipher, key):
    """
    Columnar transposition decryption - reverse the column reordering
    Args: cipher (string), key (string keyword)  
    Returns: decrypted string
    """
    n = len(key)           # Number of columns
    rows = len(cipher) // n # Number of rows
    
    # Determine original column order
    order = sorted(range(n), key=lambda k: key[k])
    
    # Create empty matrix
    matrix = [['' for _ in range(n)] for _ in range(rows)]
    
    # Fill matrix column by column in sorted order
    idx = 0
    for c in order:  # For each column in sorted order
        for r in range(rows):  # Fill that column top to bottom
            matrix[r][c] = cipher[idx]
            idx += 1
    
    # Read matrix row by row to get plaintext
    return ''.join(''.join(row) for row in matrix).rstrip('X')  # Remove padding

# USAGE EXAMPLES:
# Rail Fence: rail_fence_encrypt("HELLO", 3) → zigzag across 3 rails
# Columnar: columnar_encrypt("ATTACK", "KEY") → arrange under K-E-Y, read E-K-Y order
