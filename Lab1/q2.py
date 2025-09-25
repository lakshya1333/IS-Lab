import string

# Character set (A=0, B=1, ..., Z=25)
charset = string.ascii_uppercase


# -------------------------------------------------------
# Vigenère Cipher
# Key is repeated to match plaintext length.
# Encryption: Ci = (Pi + Ki) mod 26
# Decryption: Pi = (Ci - Ki) mod 26
# -------------------------------------------------------
class Vigenere:
    def __init__(self, msg, key):
        # Preprocess: remove spaces and convert to uppercase
        self.pt = msg.replace(" ", "").upper()
        self.key = key.upper()
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        # Extend/repeat the key to match plaintext length
        key_stream = (self.key * ((len(self.pt) // len(self.key)) + 1))[:len(self.pt)]
        # Encrypt character by character
        for p, k in zip(self.pt, key_stream):
            c = charset[(charset.index(p) + charset.index(k)) % 26]
            self.ct += c
        return self.ct

    def decrypt(self):
        pt = ""
        # Regenerate the same key stream
        key_stream = (self.key * ((len(self.ct) // len(self.key)) + 1))[:len(self.ct)]
        # Decrypt character by character
        for c, k in zip(self.ct, key_stream):
            p = charset[(charset.index(c) - charset.index(k)) % 26]
            pt += p
        return pt


# -------------------------------------------------------
# Autokey Cipher
# Starts with an initial numeric key.
# Then the plaintext itself is appended to the keystream.
# Encryption: Ci = (Pi + Ki) mod 26
# Decryption: Pi = (Ci - Ki) mod 26
# -------------------------------------------------------
class Autokey:
    def __init__(self, msg, key):
        # Preprocess: remove spaces and convert to uppercase
        self.pt = msg.replace(" ", "").upper()
        self.key = key   # Initial numeric key (integer)
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        # Key stream: [initial key] + indices of plaintext (except last char)
        key_stream = [self.key] + [charset.index(ch) for ch in self.pt[:-1]]
        # Encrypt using key stream
        for p, k in zip(self.pt, key_stream):
            c = charset[(charset.index(p) + k) % 26]
            self.ct += c
        return self.ct

    def decrypt(self):
        pt = ""
        key_stream = [self.key]  # Start with initial numeric key
        for c in self.ct:
            # Ensure key is numeric index
            k = key_stream[-1] if isinstance(key_stream[-1], int) else charset.index(key_stream[-1])
            # Decrypt character
            p = charset[(charset.index(c) - k) % 26]
            pt += p
            # Append decrypted char index to keystream
            key_stream.append(charset.index(p))
        return pt


# -------------------------------------------------------
# Driver Code
# -------------------------------------------------------
if __name__ == "__main__":
    msg = "the house is being sold tonight"

    # Vigenère with key = "dollars"
    v = Vigenere(msg, "dollars")
    enc_v = v.encrypt()
    dec_v = v.decrypt()
    print("Vigenere Encrypt:", enc_v)
    print("Vigenere Decrypt:", dec_v)

    print()

    # Autokey with initial key = 7
    a = Autokey(msg, 7)
    enc_a = a.encrypt()
    dec_a = a.decrypt()
    print("Autokey Encrypt:", enc_a)
    print("Autokey Decrypt:", dec_a)
