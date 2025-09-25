import string
charset = string.ascii_uppercase   # Define the alphabet A-Z (used for mapping indices)

# -----------------------------
# Class A: Additive Cipher
# Formula: C = (P + key) mod 26
#          P = (C - key) mod 26
# -----------------------------
class A:
    def __init__(self, msg, key):
        self.pt = msg    # Plaintext
        self.key = key   # Additive key
        self.ct = ""     # Ciphertext

    def encrypt(self):
        self.ct = ""
        for i in self.pt:
            if i.upper() in charset:   # Encrypt only letters
                ok = charset[(charset.index(i.upper()) + self.key) % 26]
                # Preserve case (upper/lower)
                if i.isupper(): 
                    self.ct += ok
                else: 
                    self.ct += ok.lower()
            else:
                self.ct += i   # Non-alphabet chars stay same
        return self.ct

    def decrypt(self):
        self.pt = ""
        for i in self.ct:
            if i.upper() in charset:   # Reverse shift by subtracting key
                ok = charset[(charset.index(i.upper()) - self.key) % 26]
                if i.isupper(): 
                    self.pt += ok
                else: 
                    self.pt += ok.lower()
            else:
                self.pt += i
        return self.pt


# -----------------------------
# Class B: Multiplicative Cipher
# Formula: C = (P × key) mod 26
#          P = (C × key⁻¹) mod 26
# -----------------------------
class B:
    def __init__(self, msg, key):
        self.pt = msg
        self.key = key   # Multiplicative key (must be coprime with 26)
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        for i in self.pt:
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) * self.key) % 26]
                if i.isupper(): 
                    self.ct += ok
                else: 
                    self.ct += ok.lower()
            else:
                self.ct += i
        return self.ct

    def decrypt(self):
        self.pt = ""
        # Find modular inverse of key mod 26
        keyinv = 1
        while (keyinv * self.key) % 26 != 1:
            keyinv += 1

        for i in self.ct:
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) * keyinv) % 26]
                if i.isupper(): 
                    self.pt += ok
                else: 
                    self.pt += ok.lower()
            else:
                self.pt += i
        return self.pt


# -----------------------------
# Class C: Affine Cipher
# Formula: C = (aP + b) mod 26
#          P = a⁻¹ (C - b) mod 26
# -----------------------------
class C:
    def __init__(self, msg, key):
        self.pt = msg
        self.a, self.b = key   # Keys: multiplicative (a), additive (b)
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        for i in self.pt:
            if i.upper() in charset:
                ok = charset[((self.a * charset.index(i.upper())) + self.b) % 26]
                if i.isupper(): 
                    self.ct += ok
                else: 
                    self.ct += ok.lower()
            else:
                self.ct += i
        return self.ct

    def decrypt(self):
        # Find modular inverse of a mod 26
        a_inv = 1
        while (a_inv * self.a) % 26 != 1:
            a_inv += 1

        self.pt = ""
        for i in self.ct:
            if i.upper() in charset:
                ok = charset[(((charset.index(i.upper()) - self.b) % 26) * a_inv) % 26]
                if i.isupper(): 
                    self.pt += ok
                else: 
                    self.pt += ok.lower()
            else:
                self.pt += i
        return self.pt


# -----------------------------
# Driver code
# -----------------------------
if __name__ == "__main__":
    m = "I am learning information security"

    # Additive Cipher
    a = A(m, 20)
    e = a.encrypt()
    d = a.decrypt()
    print(f"{e}\n{d}")
    assert d == m

    print()

    # Multiplicative Cipher
    b = B(m, 15)
    e = b.encrypt()
    d = b.decrypt()
    print(f"{e}\n{d}")
    assert d == m

    print()
    
    # Affine Cipher
    c = C(m, (15,20))
    e = c.encrypt()
    d = c.decrypt()
    print(f"{e}\n{d}")
    assert d == m
