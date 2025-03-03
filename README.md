# Polymorphic Cypher Model (polymorphic-cypher)

**polymorphic-cypher** is a Python-based symmetric encryption tool designed to produce polymorphic outputs. This means that even when encrypting the same plaintext with the same key multiple times, the ciphertext will always be different. The algorithm uses multiple layers of obfuscation to discourage straightforward reverse-engineering while maintaining a simple interface with Google-style docstrings.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Algorithm Details](#algorithm-details)
  - [Overview](#overview)
  - [Step 1: Keystream Generation](#step-1-keystream-generation)
  - [Step 2: Salt Insertion](#step-2-salt-insertion)
  - [Step 3: Final Permutation](#step-3-final-permutation)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Features

- **Polymorphic Output:** Encrypting the same plaintext with the same key yields different ciphertexts each time.
- **Layered Obfuscation:**
  - Uses an 8-byte random salt to derive a unique keystream.
  - Inserts salt bytes into the ciphertext at randomized positions determined by a seed.
  - Applies a final permutation layer to further scramble the data.
- **Plaintext Output Format:** The final ciphertext is hex-encoded, ensuring it uses only ASCII characters.
- **Simple Interface:** Provides a straightforward `encrypt(plaintext, key)` and `decrypt(ciphertext, key)` interface.
- **Google-Style Docstrings:** The code is fully documented following modern Python conventions.

## Installation

Clone the repository and navigate into the project folder. The code is compatible with Python 3.6+ and uses only standard libraries.

```bash
git clone https://github.com/yourusername/polymorphic-cypher.git
cd polymorphic-cypher
```

## Usage

```python
from polymorphic_cypher import encrypt, decrypt

text = "This is a test!"
key = "this_is_a_key"

# Encrypt the text
encrypted_text = encrypt(text, key)
print("Encrypted:", encrypted_text)

# Decrypt the text
decrypted_text = decrypt(encrypted_text, key)
print("Decrypted:", decrypted_text)
```
When running a loop, you can observe that each encryption produces a different ciphertext:
```python
for i in range(10):
    encrypted = encrypt(text, key)
    print(f"Encrypted #{i}: {encrypted}")
```

## Algorithm Details

### Overview
The **polymorphic-cypher** encryption algorithm transforms the plaintext into a uniquely-obfuscated ciphertext through several distinct stages. Each encryption produces different outputs—even for the same plaintext and key—by incorporating random elements at key steps. The following breakdown explains each step with illustrative examples.
```scss
Plaintext
   │
   ▼
[ Convert to bytes ]
   │
   ▼
[ Generate Keystream using Key & Salt ]
   │
   ▼
[ XOR Plaintext with Keystream ]
   │
   ▼
[ Insert Salt into XOR Ciphertext ]
   │
   ▼
[ Apply Final Permutation (Shuffle) ]
   │
   ▼
  Hex-encoded Ciphertext (ASCII Output) 
   │
   ▼
```
---

### Step 1: Keystream Generation & XOR Encryption

**Objective:**  
Generate a pseudorandom keystream using a combination of the user-provided key, a random salt, and an incremental counter. Then XOR the keystream with the plaintext to produce an intermediate ciphertext.

**Process:**

1. **Convert Plaintext to Bytes:**

   - **Example Plaintext:** `"This is a test!"`
   - **Plaintext Bytes (in hex):**  
     ```
     54 68 69 73 20 69 73 20 61 20 74 65 73 74 21
     ```
     (15 bytes in total.)

2. **Generate a Random Salt:**

   - **Random Salt (8 bytes, example):**  
     ```
     4C 18 03 12 51 B2 AF DD
     ```
     (This salt is generated fresh for each encryption.)

3. **Generate the Keystream:**

   - The keystream is produced by iteratively computing:
     ```
     SHA-256(key || salt || counter)
     ```
     where the counter starts at 0 and increments until the keystream is long enough.
     
   - **Illustrative Example:**  
     Suppose after processing we obtain (for the first 15 bytes):
     ```
     A1 B2 C3 D4 E5 F6 07 18 29 3A 4B 5C 6D 7E 8F
     ```
     (These are example values; actual outputs will vary.)

4. **XOR Encryption:**

   - Each plaintext byte is XORed with the corresponding keystream byte:
   
     ```
     Plaintext Byte:     54    68    69    73    ...
     Keystream Byte:     A1    B2    C3    D4    ...
     ------------------------------
     XOR Result:         F5    DA    AA    A7    ...
     ```
     
   - **Intermediate XOR Ciphertext (in hex, example):**  
     ```
     F5 DA AA A7 ... (15 bytes total)
     ```

---

### Step 2: Salt Insertion

**Objective:**  
Embed the salt into the XOR-encrypted ciphertext at predetermined, randomized positions so that it isn’t simply appended.

**Process:**

1. **Generate a Salt Insertion Seed:**

   - A 4-byte random seed is created (e.g., `0x12AB34CD`).
   - This seed is used to randomly determine positions within the output (excluding header bytes) where salt bytes will be inserted.

2. **Determine Salt Positions:**

   - **Assume:** The final output (before additional permutation) should include the original 15 XOR bytes plus the 8 salt bytes.
   - Available positions start after the header (which is 8 bytes total later on).
   - Using the seed, assume we calculate the following positions for the 8 salt bytes:
     ```
     Positions: 10, 15, 20, 25, 30, 35, 40, 45
     ```
     
3. **Insert Salt into the XOR Ciphertext:**

   - The salt bytes are interleaved into the XOR ciphertext according to the calculated positions.
   - **Example Illustration:**

     - **Before Insertion:**  
       ```
       [Byte1, Byte2, ..., Byte15]  <-- XOR ciphertext bytes
       ```
     
     - **After Insertion (positions given as indices in the combined array):**
     
       ```
       Index:   0  1  2  ...  9  [10] 11 ... 14  [15] 16 ... etc.
       Content: C1 C2 C3 ... C10 [S1] C11 ... C15 [S2] ... [S8]
       ```
       Here, `C1, C2, ...` represent XOR ciphertext bytes and `S1, S2, ...` represent salt bytes.
       
   - The result is an intermediate byte sequence that is longer by 8 bytes than the original XOR ciphertext.

---

### Step 3: Final Permutation

**Objective:**  
Further obfuscate the message by shuffling the entire intermediate data (which now contains both the XOR ciphertext and the embedded salt).

**Process:**

1. **Generate a Permutation Seed:**

   - A separate 4-byte permutation seed is generated (e.g., `0xABCD1234`).

2. **Apply Permutation:**

   - The intermediate data (post salt insertion) is shuffled based on the permutation seed.
   - **Example:**
     - **Intermediate Data (before permutation):**
       ```
       [B1, B2, B3, ..., Bn]   (where n = 15 + 8 = 23 bytes)
       ```
     - **Permutation Order (example):**
       ```
       New Order Indices: [3, 0, 7, 1, 15, 4, 2, 20, ...]
       ```
     - The byte originally at index 3 moves to the new first position, and so on.

3. **Header Construction:**

   - The final output begins with an 8-byte header:
     - **First 4 bytes:** Permutation Seed (e.g., `AB CD 12 34`)
     - **Next 4 bytes:** Salt Insertion Seed (e.g., `12 AB 34 CD`)
     
   - This header allows the decryption process to reverse both the permutation and the salt insertion.

4. **Hex-Encoding:**

   - The permuted byte array (with the header prepended) is then converted into a hex-encoded string.
   - **Final Ciphertext (example in hex):**  
     ```
     ABCD123412AB34CD...[permuted data in hex]...
     ```
     This output is guaranteed to be different each time due to the randomness in both the salt and the seeds.

---

### Summary of Decryption

To decrypt, the following reversal occurs:

1. **Extract the Header:** Retrieve the permutation seed and salt insertion seed.
2. **Reverse the Permutation:** Use the permutation seed to restore the original intermediate order.
3. **Extract the Salt:** Using the salt insertion seed, identify and remove the salt bytes from the intermediate data.
4. **Regenerate the Keystream:** With the extracted salt and the original key, recreate the keystream.
5. **XOR Decryption:** XOR the remaining ciphertext bytes with the keystream to recover the original plaintext.

Each step relies on the seeds embedded in the header, ensuring that only the correct key can reconstruct the keystream and the exact data layout.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the Repository: Click the "Fork" button on the repository page.
2. Create a Branch: Use git checkout -b feature/YourFeature to create a new branch.
3. Commit Changes: Follow standard commit message practices.
4. Submit a Pull Request: Once your changes are complete, open a pull request for review.

Please ensure your code follows Python best practices and includes Google-style docstrings.

## License
This project is licensed under the GNU v3 License. See the LICENSE file for details.

## Disclaimer

**Important**:

This encryption scheme is intended for basic obfuscation and day-to-day use in non-critical scenarios. It is not designed to provide robust cryptographic security. Potential vulnerabilities include:

* **Brute Force & Cryptanalysis**: The XOR-based encryption and permutation methods may be susceptible to cryptanalysis, especially if an attacker has access to sufficient plaintext-ciphertext pairs.
* **Key Weakness**: The security is directly tied to the quality of the provided key. Weak or reused keys can compromise the encryption.
* **Algorithm Transparency**: As the method for salt insertion and permutation is fixed, any targeted attacks on these methods might reveal information about the underlying plaintext.

For sensitive or high-security applications, it is recommended to use established cryptographic libraries and standards.

---

Feel free to review the README and let me know if you need further adjustments or have any questions!
