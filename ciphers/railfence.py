def rail_fence_encrypt(plaintext, num_rails):
    if num_rails <= 1:
        return plaintext
    
    rail = [[] for _ in range(num_rails)]
    direction = 1  # 1 = down, -1 = up
    row = 0

    for char in plaintext:
        rail[row].append(char)
        
        # Change direction at top or bottom
        if row == 0:
            direction = 1
        elif row == num_rails - 1:
            direction = -1
        
        row += direction
        
    return "".join(["".join(r) for r in rail])

def rail_fence_decrypt(ciphertext, num_rails):
    if num_rails == 1:
        return ciphertext

    # Create an empty matrix with placeholders
    marker = [['' for _ in range(len(ciphertext))] for _ in range(num_rails)]

    # First, mark the positions where letters will go
    direction = 1
    row = 0
    for col in range(len(ciphertext)):
        marker[row][col] = '*'
        row += direction
        if row == 0 or row == num_rails - 1:
            direction *= -1

    # Fill the marker matrix with letters from the ciphertext
    index = 0
    for r in range(num_rails):
        for c in range(len(ciphertext)):
            if marker[r][c] == '*' and index < len(ciphertext):
                marker[r][c] = ciphertext[index]
                index += 1

    # Now read the message in zigzag
    result = ''
    row = 0
    direction = 1
    for col in range(len(ciphertext)):
        result += marker[row][col]
        row += direction
        if row == 0 or row == num_rails - 1:
            direction *= -1

    return result



if __name__ == "__main__":
    plaintext = "hello"
    key = 3
    enc = rail_fence_encrypt(plaintext,key)
    print(enc)

    dec = rail_fence_decrypt(enc,key)
    print(dec)