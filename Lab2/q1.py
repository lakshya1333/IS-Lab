class DES:
    def __init__(self):
        self.IP = [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ]
        self.FP = [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ]
        self.E = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]
        self.P = [
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        ]
        self.S_BOXES = [
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        ]
        self.PC1 = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ]
        self.PC2 = [
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        ]
        self.SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

     # ---------------------------------------------------
    # Convert string to list of bits (8 bits per character)
    # ---------------------------------------------------
    def string_to_bits(self, text):
        bits = []
        for char in text:
            byte_val = ord(char)
            for i in range(8):
                bits.append((byte_val >> (7-i)) & 1)
        return bits

    # Convert bits back to string
    def bits_to_string(self, bits):
        text = ""
        for i in range(0, len(bits), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(bits):
                    byte_val = (byte_val << 1) | bits[i + j]
            text += chr(byte_val)
        return text

    # Convert hex string to bits
    def hex_to_bits(self, hex_string):
        bits = []
        for hex_char in hex_string:
            if hex_char.isdigit():
                val = int(hex_char)
            else:
                val = ord(hex_char.upper()) - ord('A') + 10
            for i in range(4):
                bits.append((val >> (3-i)) & 1)
        return bits

    # Convert bits to hex string
    def bits_to_hex(self, bits):
        hex_string = ""
        for i in range(0, len(bits), 4):
            val = 0
            for j in range(4):
                if i + j < len(bits):
                    val = (val << 1) | bits[i + j]
            if val < 10:
                hex_string += str(val)
            else:
                hex_string += chr(ord('A') + val - 10)
        return hex_string

    # Permutation helper
    def permute(self, bits, table):
        return [bits[i-1] for i in table]

    # Left circular shift helper
    def left_shift(self, bits, shifts):
        return bits[shifts:] + bits[:shifts]

    # XOR two bit lists
    def xor(self, bits1, bits2):
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    # S-box substitution in Feistel function
    def sbox_substitute(self, bits):
        result = []
        for i in range(8):
            start = i * 6
            six_bits = bits[start:start+6]
            row = (six_bits[0] << 1) | six_bits[5]
            col = (six_bits[1] << 3) | (six_bits[2] << 2) | (six_bits[3] << 1) | six_bits[4]
            val = self.S_BOXES[i][row][col]
            for j in range(4):
                result.append((val >> (3-j)) & 1)
        return result

    # Generate 16 round keys
    def generate_round_keys(self, key_bits):
        key_56 = self.permute(key_bits, self.PC1)
        left = key_56[:28]
        right = key_56[28:]
        round_keys = []
        for round_num in range(16):
            left = self.left_shift(left, self.SHIFTS[round_num])
            right = self.left_shift(right, self.SHIFTS[round_num])
            combined = left + right
            round_key = self.permute(combined, self.PC2)
            round_keys.append(round_key)
        return round_keys

    # Feistel function (F function)
    def feistel_function(self, right_half, round_key):
        expanded = self.permute(right_half, self.E)
        xored = self.xor(expanded, round_key)
        substituted = self.sbox_substitute(xored)
        result = self.permute(substituted, self.P)
        return result

    # Encrypt one 64-bit block
    def des_encrypt_block(self, plaintext_bits, round_keys):
        permuted = self.permute(plaintext_bits, self.IP)
        left = permuted[:32]
        right = permuted[32:]
        for round_num in range(16):
            old_right = right[:]
            f_result = self.feistel_function(right, round_keys[round_num])
            right = self.xor(left, f_result)
            left = old_right
        combined = right + left
        ciphertext = self.permute(combined, self.FP)
        return ciphertext

    # Decrypt one 64-bit block (reverse round keys)
    def des_decrypt_block(self, ciphertext_bits, round_keys):
        reversed_keys = round_keys[::-1]
        return self.des_encrypt_block(ciphertext_bits, reversed_keys)

    # Padding for messages not multiple of 8 bytes
    def pad_message(self, message):
        pad_len = 8 - (len(message) % 8)
        return message + chr(pad_len) * pad_len

    # Remove padding after decryption
    def unpad_message(self, message):
        if not message:
            return message
        pad_len = ord(message[-1])
        return message[:-pad_len]

    # ---------------------------------------------------
    # Full message encryption
    # ---------------------------------------------------
    def encrypt(self, plaintext, key):
        if len(key) < 8:
            key = key.ljust(8, '\x00')  # pad key if < 8 bytes
        elif len(key) > 8:
            key = key[:8]               # truncate key if > 8 bytes
        key_bits = self.string_to_bits(key)
        round_keys = self.generate_round_keys(key_bits)
        padded_plaintext = self.pad_message(plaintext)
        ciphertext_bits = []
        for i in range(0, len(padded_plaintext), 8):
            block = padded_plaintext[i:i+8]
            block_bits = self.string_to_bits(block)
            encrypted_block = self.des_encrypt_block(block_bits, round_keys)
            ciphertext_bits.extend(encrypted_block)
        return ciphertext_bits

    # ---------------------------------------------------
    # Full message decryption
    # ---------------------------------------------------
    def decrypt(self, ciphertext_bits, key):
        if len(key) < 8:
            key = key.ljust(8, '\x00')
        elif len(key) > 8:
            key = key[:8]
        key_bits = self.string_to_bits(key)
        round_keys = self.generate_round_keys(key_bits)
        plaintext_bits = []
        for i in range(0, len(ciphertext_bits), 64):
            block = ciphertext_bits[i:i+64]
            decrypted_block = self.des_decrypt_block(block, round_keys)
            plaintext_bits.extend(decrypted_block)
        plaintext = self.bits_to_string(plaintext_bits)
        return self.unpad_message(plaintext)

# -------------------------------------------------------
# Demonstration: Encrypt & Decrypt "Confidential Data"
# -------------------------------------------------------
def demonstrate_des():
    des = DES()
    message = "Confidential Data"
    key = "A1B2C3D4"          # DES key (8 bytes)
    ciphertext_bits = des.encrypt(message, key)
    decrypted_message = des.decrypt(ciphertext_bits, key)
    ciphertext_hex = des.bits_to_hex(ciphertext_bits)
    return ciphertext_hex, decrypted_message

if __name__ == "__main__":
    ct, pt = demonstrate_des()
    print("Ciphertext (hex):", ct)
    print("Decrypted:", pt)