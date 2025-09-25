
# Get input string from user
input_string = input("Enter string to be hashed: ")

def hash(input_string):
    # Initialize hash with djb2 algorithm's magic number (prime number for good distribution)
    hash_value = 5381
    
    # 32-bit mask to keep hash value within 32-bit range (prevents overflow)
    mask = 0xFFFFFFFF
    
    # Define bit shift amounts for additional mixing operations
    shift1, shift2, shift3 = 16, 4, 3
    
    # Process each character in the input string
    for char in input_string:
        # djb2 hash: multiply by 33 and add ASCII value of character
        # This is the core djb2 algorithm: hash = hash * 33 + char
        hash_value = (hash_value * 33) + ord(char)

        # Additional mixing operations to improve hash distribution:
        # XOR with left-shifted version (spreads bits to higher positions)
        hash_value ^= (hash_value << shift1)
        
        # XOR with right-shifted version (brings higher bits to lower positions)
        hash_value ^= (hash_value >> shift2)
        
        # XOR with another left-shifted version (further bit mixing)
        hash_value ^= (hash_value << shift3)
        
        # Apply 32-bit mask to keep hash value within bounds and prevent overflow
        hash_value &= mask
        
    # Return the final computed hash value
    return hash_value

# Display the hashed result
print("Hashed Value: ", hash(input_string))


        