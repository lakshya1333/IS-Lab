import string

class Playfair:
    def __init__(self, key):
        # Convert key to uppercase and replace J with I (Playfair uses 25 letters)
        self.key = key.upper().replace("J", "I")
        self.matrix = self._generate_matrix()  # Build the 5x5 Playfair matrix

    # -----------------------------
    # Generate 5x5 Playfair matrix
    # Start with the key, then fill in remaining alphabet letters
    # -----------------------------
    def _generate_matrix(self):
        seen = set()     # Keep track of letters already added
        matrix = []

        # Add unique letters from the key first
        for ch in self.key:
            if ch not in seen and ch in string.ascii_uppercase:
                seen.add(ch)
                matrix.append(ch)

        # Add the rest of the alphabet (excluding J, already merged with I)
        for ch in string.ascii_uppercase:
            if ch == "J":
                continue
            if ch not in seen:
                seen.add(ch)
                matrix.append(ch)

        # Split into 5x5 matrix
        return [matrix[i:i+5] for i in range(0, 25, 5)]

    # -----------------------------
    # Helper: Find position of a letter in matrix
    # Returns row, column
    # -----------------------------
    def _pos(self, ch):
        for r in range(5):
            for c in range(5):
                if self.matrix[r][c] == ch:
                    return r, c
        return None

    # -----------------------------
    # Prepare plaintext for encryption
    # 1. Uppercase and remove spaces
    # 2. Replace J with I
    # 3. Break into digraphs (pairs of 2 letters)
    # 4. Insert 'X' if letters in pair are the same or odd length padding
    # -----------------------------
    def _prepare_text(self, text):
        text = text.upper().replace(" ", "").replace("J", "I")
        digraphs = []
        i = 0
        while i < len(text):
            a = text[i]
            b = ""
            if i+1 < len(text):
                b = text[i+1]
                if a == b:  # Same letters → insert 'X'
                    b = "X"
                    i += 1
                else:
                    i += 2
            else:  # Last lonely char → pad with 'X'
                b = "X"
                i += 1
            digraphs.append(a+b)
        return digraphs

    # -----------------------------
    # Encryption rules:
    # 1. Same row → take letter to the right
    # 2. Same column → take letter below
    # 3. Rectangle → swap columns
    # -----------------------------
    def encrypt(self, plaintext):
        digraphs = self._prepare_text(plaintext)
        ciphertext = ""
        for pair in digraphs:
            a, b = pair[0], pair[1]
            ra, ca = self._pos(a)
            rb, cb = self._pos(b)

            if ra == rb:  # Same row
                ciphertext += self.matrix[ra][(ca+1) % 5]
                ciphertext += self.matrix[rb][(cb+1) % 5]
            elif ca == cb:  # Same column
                ciphertext += self.matrix[(ra+1) % 5][ca]
                ciphertext += self.matrix[(rb+1) % 5][cb]
            else:  # Rectangle → swap columns
                ciphertext += self.matrix[ra][cb]
                ciphertext += self.matrix[rb][ca]
        return ciphertext

    # -----------------------------
    # Decryption rules (inverse of encryption):
    # 1. Same row → take letter to the left
    # 2. Same column → take letter above
    # 3. Rectangle → swap columns
    # -----------------------------
    def decrypt(self, ciphertext):
        plaintext = ""
        i = 0
        while i < len(ciphertext):
            a, b = ciphertext[i], ciphertext[i+1]
            ra, ca = self._pos(a)
            rb, cb = self._pos(b)

            if ra == rb:  # Same row
                plaintext += self.matrix[ra][(ca-1) % 5]
                plaintext += self.matrix[rb][(cb-1) % 5]
            elif ca == cb:  # Same column
                plaintext += self.matrix[(ra-1) % 5][ca]
                plaintext += self.matrix[(rb-1) % 5][cb]
            else:  # Rectangle → swap columns
                plaintext += self.matrix[ra][cb]
                plaintext += self.matrix[rb][ca]
            i += 2
        return plaintext


# -----------------------------
# Driver Code
# -----------------------------
if __name__ == "__main__":
    key = "GUIDANCE"
    msg = "The key is hidden under the door pad"

    pf = Playfair(key)
    enc = pf.encrypt(msg)
    dec = pf.decrypt(enc)

    # Print Playfair matrix
    print("Matrix:")
    for row in pf.matrix:
        print(row)

    print("\nPlaintext:", msg)
    print("Ciphertext:", enc)
    print("Decrypted:", dec)
