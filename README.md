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
The polymorphic-cypher algorithm uses a multi-step process to ensure that the same plaintext produces different ciphertexts each time. The process can be visualized in the following steps:
```scss
Plaintext
   │
   ▼
[ Convert to bytes ]
   │
   ▼
[ XOR Encryption using Keystream ]
   │
   ▼
[ Salt Insertion at random positions ]
   │
   ▼
[ Final Permutation (shuffle) ]
   │
   ▼
Hex-encoded Ciphertext (ASCII output)
```
### Step 1: Keystream Generation
A pseudorandom keystream is generated using SHA-256 as follows:

```ini
keystream = SHA-256(key || salt || counter)
```
- key: The user-provided encryption key.
- salt: An 8-byte random value generated for each encryption.
- counter: An incremental counter to ensure that enough keystream bytes are generated.

The keystream is then used to XOR-encrypt the plaintext bytes.

### Step 2: Salt Insertion
After XOR encryption, the salt is interleaved into the ciphertext. The positions for salt insertion are determined by a random 4-byte seed. For example:

```yaml
XOR-encrypted ciphertext:  C1, C2, C3, C4, C5, C6, ... , Cn
Salt bytes:                S1, S2, ..., S8
```

Using the seed, positions might be determined (e.g., 10, 15, 20, ...), and the salt bytes are inserted at these positions, ensuring the salt is not merely appended but embedded within the ciphertext.

### Step 3: Final Permutation
To further obfuscate the ciphertext, a final permutation layer is applied:
- A separate 4-byte permutation seed is generated.
- The entire data (post salt-insertion) is shuffled based on this seed.

The final output structure is as follows:
```css
[ 4 bytes: Permutation Seed ]
[ 4 bytes: Salt Insertion Seed ]
[ Permuted Data (XOR ciphertext with embedded salt) ]
```
The output is then hex-encoded for ASCII compatibility.

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
