# Lab Exercise 2: Public-Key Searchable Encryption (PKSE)
# -------------------------------------------------------
# This program demonstrates a basic PKSE implementation using the Paillier cryptosystem.
#
# Steps:
# 2a. Create a dataset of 10+ documents.
# 2b. Implement encryption and decryption functions using Paillier.
# 2c. Build an encrypted inverted index mapping words -> encrypted document IDs.
# 2d. Implement search function:
#     - Encrypt query using public key.
#     - Match against encrypted index.
#     - Decrypt results using private key.

from phe import paillier  # Paillier library for homomorphic encryption
from hashlib import sha256  # SHA-256 for deterministic hashing of words

# -------------------------------------------------------
# 2b. Key Generation
# -------------------------------------------------------
def generate_keys():
    """
    Generate Paillier public and private key pair.
    - Public key is used to encrypt data (doc IDs, queries).
    - Private key is used to decrypt encrypted doc IDs.
    """
    pubkey, privkey = paillier.generate_paillier_keypair()
    return pubkey, privkey


# -------------------------------------------------------
# 2b. Encryption & Decryption Functions
# -------------------------------------------------------
def encrypt_data(pubkey, data):
    """
    Encrypt string data (doc ID) using Paillier.
    Steps:
    - Convert string doc ID to integer (Paillier works on numbers).
    - Encrypt integer using public key.
    - Return Paillier encrypted number.
    """
    doc_id_int = int.from_bytes(data.encode(), byteorder='big')
    encrypted = pubkey.encrypt(doc_id_int)
    return encrypted


def decrypt_data(privkey, encrypted):
    """
    Decrypt Paillier-encrypted integer back to doc ID string.
    Steps:
    - Decrypt integer using private key.
    - Convert integer back to bytes, then decode to string.
    """
    doc_id_int = privkey.decrypt(encrypted)
    doc_id_bytes = doc_id_int.to_bytes((doc_id_int.bit_length() + 7)//8, byteorder='big')
    return doc_id_bytes.decode()


# -------------------------------------------------------
# 2c. Build Encrypted Inverted Index
# -------------------------------------------------------
def create_index(documents, pubkey):
    """
    Build an encrypted inverted index:
    - For each document and each word in the document:
        - Hash the word (SHA-256) to create a deterministic token.
        - Encrypt the document ID using Paillier public key.
        - Store encrypted doc IDs under the hashed token.
    """
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            # Deterministic token for each word using SHA-256
            word_token = sha256(word.encode()).hexdigest()

            # Encrypt document ID using Paillier
            encrypted_doc_id = encrypt_data(pubkey, doc_id)

            # Add encrypted doc ID to the index under the word token
            if word_token not in index:
                index[word_token] = []
            index[word_token].append(encrypted_doc_id)
    return index


# -------------------------------------------------------
# 2d. Encrypted Search Function
# -------------------------------------------------------
def search(index, query, privkey):
    """
    Search for a query in the encrypted index:
    - Hash the query word (deterministic).
    - Retrieve encrypted document IDs from the index.
    - Decrypt each document ID using private key.
    - Return list of matching document IDs.
    """
    query_token = sha256(query.encode()).hexdigest()
    if query_token in index:
        encrypted_doc_ids = index[query_token]

        # Decrypt all matching document IDs
        doc_ids = [decrypt_data(privkey, doc_id) for doc_id in encrypted_doc_ids]
        return doc_ids
    else:
        # Return empty list if query token not found
        return []


# -------------------------------------------------------
# 2a. Example Dataset (10 Documents)
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
# Demo: Build and Search Encrypted Index
# -------------------------------------------------------
pubkey, privkey = generate_keys()  # Generate Paillier keypair
encrypted_index = create_index(documents, pubkey)
print("Encrypted index successfully created with Paillier encryption.\n")

query = "document"  # Search query
results = search(encrypted_index, query, privkey)

# Display search results
print(f"Search results for query '{query}':")
if results:
    for doc_id in results:
        print(f" - {doc_id}")
else:
    print("No documents found.")