# HASH ALGORITHM COMPARISON TOOL
# Compares performance and collision detection for MD5, SHA-1, and SHA-256
# Generates random test data and visualizes results with matplotlib

import hashlib
import random
import string
import time
import matplotlib.pyplot as plt

def generate_random_strings(n, min_len=5, max_len=20):
    """
    Generate random alphanumeric strings for hash testing
    Args: n (int) - number of strings to generate
          min_len (int) - minimum string length
          max_len (int) - maximum string length
    Returns: list of random strings
    """
    strings = []
    for _ in range(n):
        length = random.randint(min_len, max_len)  # Random length in range
        # Generate random string with letters and digits
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        strings.append(s)
    return strings

def compute_hashes(strings, hash_func_name):
    """
    Compute hashes for all strings using specified algorithm and measure time
    Args: strings (list) - input strings to hash
          hash_func_name (str) - hash algorithm name ('md5', 'sha1', 'sha256')
    Returns: (hashes_list, elapsed_time_seconds)
    """
    hash_func = getattr(hashlib, hash_func_name)  # Get hash function by name
    hashes = []
    start_time = time.time()                      # Start timing
    
    for s in strings:
        h = hash_func(s.encode()).hexdigest()     # Hash string as bytes, get hex digest
        hashes.append(h)
    
    elapsed = time.time() - start_time            # Calculate elapsed time
    return hashes, elapsed

def detect_collisions(hashes):
    """
    Detect hash collisions (same hash for different inputs)
    Args: hashes (list) - list of hash values
    Returns: list of duplicate hash values
    
    Note: True collisions are extremely rare for cryptographic hashes,
    but this helps demonstrate collision detection methods
    """
    seen = set()       # Track hash values we've seen
    collisions = []    # Store duplicate hashes
    
    for h in hashes:
        if h in seen:
            collisions.append(h)  # Found a collision
        else:
            seen.add(h)           # First time seeing this hash
    return collisions

def main():
    """
    Main function: Generate test data, compare hash algorithms, and plot results
    """
    # Generate random test data
    n = random.randint(50, 100)  # Random number of test strings
    print(f"Generating {n} random strings...")
    data = generate_random_strings(n)

    # Hash algorithms to compare
    hash_algorithms = ['md5', 'sha1', 'sha256']
    times = []           # Store computation times
    collision_counts = [] # Store collision counts

    # Test each hash algorithm
    for algo in hash_algorithms:
        print(f"\nAnalyzing {algo.upper()}...")
        hashes, elapsed = compute_hashes(data, algo)    # Compute hashes and time
        collisions = detect_collisions(hashes)          # Check for collisions
        
        print(f"Time taken: {elapsed:.6f} seconds")
        print(f"Collisions detected: {len(collisions)}")
        
        times.append(elapsed)                           # Store results for plotting
        collision_counts.append(len(collisions))

    # Create visualization comparing algorithms
    plt.figure(figsize=(10,5))

    # Plot computation time as line graph
    plt.plot(hash_algorithms, times, marker='o', linestyle='-', color='blue', label='Computation Time (s)')
    # Add time values as text labels
    for i, t in enumerate(times):
        plt.text(i, t, f"{t:.4f}", ha='center', va='bottom')

    # Plot collision count as dashed line
    plt.plot(hash_algorithms, collision_counts, marker='s', linestyle='--', color='red', label='Collisions')

    plt.title('Hashing Algorithms: Computation Time & Collisions')
    plt.xlabel('Hash Algorithm')
    plt.ylabel('Value')
    plt.legend()
    plt.grid(True)   # Add grid for better readability
    plt.show()       # Display the plot

# HASH ALGORITHM NOTES:
# MD5 (128-bit):
#   - Fastest but cryptographically broken
#   - Vulnerable to collision attacks
#   - Should NOT be used for security purposes
#
# SHA-1 (160-bit):
#   - Moderate speed, also cryptographically broken
#   - Deprecated for security applications
#   - Still used for non-security checksums
#
# SHA-256 (256-bit):
#   - Slower but cryptographically secure
#   - Part of SHA-2 family
#   - Recommended for security applications

if __name__ == "__main__":
    main()