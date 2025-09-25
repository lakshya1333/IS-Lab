# 3. Encrypt the message "Cryptographic Protocols" using the RSA public key (n, e)
# where n = 323 and e = 5. Decrypt the ciphertext with the private key (n, d) where d
# = 173 to confirm the original message 

# Step 1: Define the plaintext message
# Step 1: Define the plaintext message
pt = "Cryptographic Protocols"

# Step 2: RSA key parameters (given)
n = 323    # modulus
e = 5      # public exponent
d = 173    # private exponent

# Step 3: Encrypt each character individually
# Each character's ASCII value is less than n, so it fits
ciphertext = []
for char in pt:
    c = pow(ord(char), e, n)  # RSA encryption: c = m^e mod n
    ciphertext.append(c)

print(f"Ciphertext (per character): {ciphertext}")

# Step 4: Decrypt each character individually
decrypted_chars = []
for c in ciphertext:
    m = pow(c, d, n)           # RSA decryption: m = c^d mod n
    decrypted_chars.append(chr(m))  # Convert back to character

# Step 5: Join decrypted characters to form the original message
mes = ''.join(decrypted_chars)

# Step 6: Display decrypted message and verification
print(f"Decrypted message: {mes}")
print(f"Original == Decrypted: {pt == mes}")
