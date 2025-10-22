# Lab Exercise 1: Searchable Symmetric Encryption (SSE)
# -------------------------------------------------------
# This program demonstrates a basic implementation of Searchable Symmetric Encryption (SSE)
# using AES encryption in Python.
#
# Steps:
# 1a. Create a dataset of 10 text documents.
# 1b. Implement AES encryption/decryption (deterministic for tokens, randomized for data).
# 1c. Build an inverted index mapping words -> encrypted document IDs.
# 1d. Implement encrypted search that retrieves and decrypts matching document IDs.
#
# Note:
# - AES-ECB mode is used for deterministic encryption of words (for token matching).
# - AES-CBC mode is used for encrypting document IDs securely (randomized with IV).
# - Hashing (SHA-256) is applied to words before encryption for normalization and security.

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

# -------------------------------------------------------
# 1b. AES Encryption & Decryption Functions
# -------------------------------------------------------

def deterministic_encrypt(key, data):
    """
    Perform deterministic AES encryption (no random IV).
    This allows identical words to produce identical ciphertexts,
    enabling encrypted search matching.
    NOTE: AES-ECB is not semantically secure — used here only for SSE demo.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext


def encrypt_data(key, data):
    """
    Encrypt data using AES-CBC with a random IV (secure for document IDs).
    Returns both IV and ciphertext (since IV is required for decryption).
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Generate a random IV for each encryption
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext


def decrypt_data(key, iv, ciphertext):
    """
    Decrypt AES-CBC encrypted data using the provided IV.
    Returns plaintext as a UTF-8 decoded string.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


# -------------------------------------------------------
# 1c. Create Encrypted Inverted Index
# -------------------------------------------------------

def create_index(documents, key):
    """
    Build an encrypted inverted index.

    Steps:
    - Split each document into words.
    - Hash each word (using SHA-256) for normalization.
    - Deterministically encrypt the hash to create an encrypted token.
    - Encrypt the document ID (using AES-CBC with a random IV).
    - Store the encrypted doc IDs (and their IVs) under the encrypted token key.
    """
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            # Normalize word using SHA-256 hash
            word_hash = hashlib.sha256(word.encode()).digest()

            # Deterministically encrypt the hashed word (for consistent token matching)
            token = deterministic_encrypt(key, word_hash)

            # Encrypt the document ID (non-deterministically)
            iv_doc_id, enc_doc_id = encrypt_data(key, doc_id)

            # Store encrypted doc IDs in the index under the token
            if token not in index:
                index[token] = []
            index[token].append((iv_doc_id, enc_doc_id))  # Store tuple (IV, ciphertext)
    return index


# -------------------------------------------------------
# 1d. Search Function (Encrypted Query)
# -------------------------------------------------------

def search(index, query, key):
    """
    Search for an encrypted query term within the encrypted index.

    Steps:
    - Hash and deterministically encrypt the query term to match stored tokens.
    - If the encrypted token exists in the index, decrypt all associated document IDs.
    - Return and print the matching document IDs.
    """
    # Normalize and encrypt the query word
    query_hash = hashlib.sha256(query.encode()).digest()
    query_token = deterministic_encrypt(key, query_hash)

    # Look up encrypted token in the index
    if query_token in index:
        encrypted_doc_ids = index[query_token]
        results = []

        # Decrypt each stored document ID
        for iv_doc_id, enc_doc_id in encrypted_doc_ids:
            doc_id = decrypt_data(key, iv_doc_id, enc_doc_id)
            results.append(doc_id)
        return results
    else:
        # Return empty if token not found
        return []


# -------------------------------------------------------
# 1a. Example Dataset (10+ Documents)
# -------------------------------------------------------

documents = {
    "doc1": "this is a document with some words",
    "doc2": "another document with different words",
    "doc3": "yet another document with some common words",
    "doc4": "more text data to search within",
    "doc5": "data privacy and encryption techniques",
    "doc6": "secure searchable encryption example",
    "doc7": "confidential data must stay safe",
    "doc8": "indexing and querying encrypted data",
    "doc9": "efficient search on encrypted datasets",
    "doc10": "modern cryptographic methods for privacy"
}

# -------------------------------------------------------
# Demo: Building and Searching the Encrypted Index
# -------------------------------------------------------

# Generate a random AES key
key = get_random_bytes(16)

# Build the encrypted inverted index
encrypted_index = create_index(documents, key)
print("Encrypted index successfully created.\n")

# Perform an encrypted search query
query = "document"
results = search(encrypted_index, query, key)

# Display results
print(f"Search results for query '{query}':")
if results:
    for doc_id in results:
        print(f" - {doc_id}")
else:
    print("No documents found.")

