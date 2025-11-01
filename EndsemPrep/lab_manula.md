Got it ✅ — so based on your **ICT3141 Information Security Lab Manual**, the algorithms in your *syllabus* are strictly limited to:

### 🔐 Symmetric Algorithms

* **DES, AES** (under Lab 2)

### 🔑 Asymmetric Algorithms

* **RSA, ElGamal, ECC, Rabin, Diffie–Hellman** (Labs 3 & 4)

### 🧾 Hashing & Signatures

* **MD5, SHA-1, SHA-256** (Lab 5)
* **RSA-based and ElGamal/Schnorr Digital Signatures** (Lab 6)

### 🧮 Advanced / Privacy-Preserving

* **Paillier (Additive Homomorphic)**
* **RSA (Multiplicative Homomorphic)**
* **ElGamal (Multiplicative Homomorphic)**
  *(Lab 7)*

### 🔍 Searchable Encryption

* **SSE (AES-based)**
* **PKSE (Paillier-based)**
  *(Lab 8)*

---

So if someone asks you for **alternate algorithms** for your “Privacy-Preserving Medical Record Management System” question, *within your syllabus*, the valid alternates would be:

| Function                                    | Given Algo                  | Alternate (Allowed in ICT3141 Syllabus) | Why                                                                   |
| ------------------------------------------- | --------------------------- | --------------------------------------- | --------------------------------------------------------------------- |
| AES-256 (report encryption)                 | ✅ AES                       | **DES / Triple DES**                    | Legacy symmetric encryption covered in Lab 2                          |
| RSA (key encryption / homomorphic)          | ✅ RSA                       | **Rabin**                               | Both are public-key systems, RSA for encryption, Rabin for efficiency |
| ElGamal (digital signature)                 | ✅ ElGamal                   | **Schnorr / RSA Digital Signature**     | All are asymmetric signature schemes from Lab 6                       |
| Paillier (department info – additive HE)    | ✅ Paillier                  | **RSA (multiplicative HE)**             | Both are partial homomorphic systems covered in Lab 7                 |
| RSA-based homomorphic encryption (expenses) | ✅ RSA                       | **ElGamal (multiplicative HE)**         | Also supports homomorphic multiplication                              |
| Auditor search (Searchable Encryption)      | ✅ Paillier / AES (SSE/PKSE) | **AES-based SSE**                       | Both SSE and PKSE are in Lab 8                                        |
| Key exchange (if used)                      | Diffie–Hellman (optional)   | **ECC (ECDH)**                          | Both included in Labs 3–4                                             |

---

### 💬 In summary:

For your project and viva prep, **these alternates are syllabus-safe**:

* **AES ↔ DES / Triple DES**
* **RSA ↔ Rabin / ECC**
* **ElGamal ↔ Schnorr / RSA Signatures**
* **Paillier ↔ RSA / ElGamal (for homomorphic ops)**
* **PKSE ↔ SSE (AES-based)**

---

Would you like me to make a **viva-ready answer sheet** where for each original algorithm, I give a 2-line explanation of *why* it could be replaced by the alternate — like “if asked in exam, say this”? It’ll make you sound pro during your evaluation.
