from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json

def generate_paillier_keys():
    pub, priv = paillier.generate_paillier_keypair()
    return pub, priv

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

def rsa_sign(private_key, message_str):
    h = SHA256.new(message_str.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def rsa_verify(public_key, message_str, signature):
    h = SHA256.new(message_str.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# --- Summary and Display Function ---

def format_summary(summary_data):
    """Formats and prints the transaction summary table."""
    print("\n" + "="*80)
    print("🌟 **COMPREHENSIVE TRANSACTION SUMMARY** 🌟")
    print("="*80)

    for seller_name, data in summary_data.items():
        print(f"\n### SELLER: **{seller_name}**")
        
        # Table for Individual Transactions
        print("\n| Transaction Amount (Plain) | Encrypted Amount (Partial) | Decrypted Amount (Verification) |")
        print("|:--------------------------:|:------------------------------:|:-------------------------------:|")
        for i in range(len(data['Individual Transaction Amounts'])):
            plain = data['Individual Transaction Amounts'][i]
            # Print only a snippet of the large integer for readability
            encrypted_snippet = str(data['Encrypted Transaction Amounts'][i].ciphertext()[:20]) + "..." 
            decrypted = data['Decrypted Transaction Amounts'][i]
            print(f"| $ {plain:<24} | {encrypted_snippet:<30} | $ {decrypted:<27} |")

        # Summary Totals and Signature
        print("\n--- Totals and Verification ---")
        print(f"* **Total Encrypted Amount (Homomorphic Sum):** {str(data['Total Encrypted Transaction Amount'].ciphertext()[:30])}...")
        print(f"* **Total Decrypted Amount:** **$ {data['Total Decrypted Transaction Amount']}**")
        print(f"* **Digital Signature Status:** {data['Digital Signature Status']}")
        print(f"* **Signature Verification Result:** **{'✅ SUCCESS' if data['Signature Verification Result'] else '❌ FAILURE'}**")
    
    print("\n" + "="*80)