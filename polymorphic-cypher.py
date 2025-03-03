"""
Polymorphic Cipher Model

This module implements a symmetric encryption scheme with polymorphic outputs.
It uses a multi-layered approach for obfuscation:
  1. A random 8-byte salt is generated and used to derive a keystream via iterative hashing.
  2. The plaintext is XOR-encrypted with the keystream.
  3. The salt bytes are interleaved into the ciphertext at positions determined by a random salt seed.
  4. An extra permutation layer is applied to the combined data using a separate permutation seed.

Both seeds (permutation and salt) are embedded in an 8-byte header so that decryption can reverse the process.
The final output is hex-encoded, ensuring the ciphertext uses only plain ASCII characters.

Functions:
  - encrypt(plaintext: str, key: str) -> str
  - decrypt(ciphertext: str, key: str) -> str
"""

import hashlib
import secrets
import random
from typing import List


def generate_keystream(key: bytes, salt: bytes, length: int) -> bytes:
    """Generate a pseudorandom keystream of a given length.

    This function uses iterative SHA-256 hashing on the concatenation of the key, salt, and a counter.

    Args:
        key (bytes): The encryption key in byte format.
        salt (bytes): The salt bytes.
        length (int): The desired length of the keystream.

    Returns:
        bytes: A keystream of the specified length.
    """
    keystream = b""
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        block = hashlib.sha256(key + salt + counter_bytes).digest()
        keystream += block
        counter += 1
    return keystream[:length]


def get_salt_positions_from_seed(seed: int, cipher_length: int, salt_length: int) -> List[int]:
    """Determine positions for salt insertion using a random seed.

    The available positions are within the region after an 8-byte header. The salt bytes
    are inserted at positions determined by shuffling these available indices.

    Args:
        seed (int): A random seed to determine the salt positions.
        cipher_length (int): The length of the XOR-encrypted plaintext.
        salt_length (int): The number of salt bytes.

    Returns:
        List[int]: Sorted list of positions (indices) where salt bytes will be inserted.
    """
    total_length = cipher_length + salt_length + 8  # 8 bytes reserved for header
    positions = list(range(8, total_length))
    rng = random.Random(seed)
    rng.shuffle(positions)
    return sorted(positions[:salt_length])


def apply_final_permutation(data: bytearray, perm_seed: int) -> bytearray:
    """Apply a permutation to the data using a given seed.

    This final permutation shuffles the data to provide an extra layer of obfuscation.

    Args:
        data (bytearray): The bytearray data to be permuted.
        perm_seed (int): The random seed used for permutation.

    Returns:
        bytearray: A new bytearray with permuted data.
    """
    indices = list(range(len(data)))
    rng = random.Random(perm_seed)
    rng.shuffle(indices)
    permuted = bytearray(len(data))
    for i, pos in enumerate(indices):
        permuted[i] = data[pos]
    return permuted


def reverse_final_permutation(data: bytearray, perm_seed: int) -> bytearray:
    """Reverse the permutation applied by `apply_final_permutation`.

    This function reconstructs the original order of the data.

    Args:
        data (bytearray): The permuted bytearray data.
        perm_seed (int): The same seed used during permutation.

    Returns:
        bytearray: The data in its original order.
    """
    n = len(data)
    indices = list(range(n))
    rng = random.Random(perm_seed)
    rng.shuffle(indices)
    original = bytearray(n)
    for permuted_index, original_index in enumerate(indices):
        original[original_index] = data[permuted_index]
    return original


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt plaintext using the polymorphic cipher algorithm.

    The encryption process includes:
      1. Converting plaintext to bytes.
      2. Generating an 8-byte random salt.
      3. Deriving a keystream from the key and salt.
      4. XOR-encrypting the plaintext.
      5. Inserting the salt into the ciphertext at positions determined by a 4-byte salt seed.
      6. Applying a final permutation layer using an additional 4-byte permutation seed.
      7. Prepending an 8-byte header (permutation seed + salt seed) and hex-encoding the result.

    Args:
        plaintext (str): The plaintext message to encrypt.
        key (str): The encryption key.

    Returns:
        str: The final hex-encoded ciphertext.
    """
    plaintext_bytes = plaintext.encode("utf-8")
    cipher_length = len(plaintext_bytes)
    salt_length = 8  # fixed salt length

    # Generate random salt and salt seed.
    salt = secrets.token_bytes(salt_length)
    salt_seed = secrets.randbits(32)
    salt_seed_bytes = salt_seed.to_bytes(4, byteorder="big")

    # Generate keystream and perform XOR encryption.
    key_bytes = key.encode("utf-8")
    keystream = generate_keystream(key_bytes, salt, cipher_length)
    cipher_bytes = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream)])

    # Determine final output length and salt positions.
    final_length = cipher_length + salt_length + 8  # 8 header bytes
    salt_positions = get_salt_positions_from_seed(salt_seed, cipher_length, salt_length)

    # Build the intermediate output (after header) with salt interleaved.
    intermediate = bytearray(final_length - 8)  # exclude header for now
    cipher_index = 0
    salt_index = 0
    for i in range(8, final_length):
        if salt_index < salt_length and i == salt_positions[salt_index]:
            intermediate[i - 8] = salt[salt_index]
            salt_index += 1
        else:
            intermediate[i - 8] = cipher_bytes[cipher_index]
            cipher_index += 1

    # Generate and embed the permutation seed.
    perm_seed = secrets.randbits(32)
    perm_seed_bytes = perm_seed.to_bytes(4, byteorder="big")
    permuted_data = apply_final_permutation(intermediate, perm_seed)

    # Construct the final output: header + permuted data.
    final_output = perm_seed_bytes + salt_seed_bytes + permuted_data
    return final_output.hex()


def decrypt(ciphertext: str, key: str) -> str:
    """Decrypt ciphertext produced by the polymorphic cipher algorithm.

    The decryption process:
      1. Converts the hex-encoded ciphertext to bytes.
      2. Extracts the 8-byte header (4-byte permutation seed and 4-byte salt seed).
      3. Reverses the final permutation.
      4. Extracts the salt bytes from the intermediate data.
      5. Regenerates the keystream using the extracted salt.
      6. XORs the cipher bytes with the keystream to recover the original plaintext.

    Args:
        ciphertext (str): The hex-encoded ciphertext.
        key (str): The decryption key.

    Returns:
        str: The recovered plaintext.
    """
    full_bytes = bytearray.fromhex(ciphertext)
    total_length = len(full_bytes)
    header_length = 8
    salt_length = 8
    remaining_length = total_length - header_length
    cipher_length = remaining_length - salt_length

    # Extract header seeds.
    perm_seed_bytes = full_bytes[0:4]
    salt_seed_bytes = full_bytes[4:8]
    perm_seed = int.from_bytes(perm_seed_bytes, byteorder="big")
    salt_seed = int.from_bytes(salt_seed_bytes, byteorder="big")

    # Reverse the final permutation.
    permuted_data = full_bytes[8:]
    intermediate = reverse_final_permutation(permuted_data, perm_seed)

    # Determine salt positions and extract salt and cipher bytes.
    salt_positions = get_salt_positions_from_seed(salt_seed, cipher_length, salt_length)
    salt = bytearray(salt_length)
    cipher_bytes = bytearray(cipher_length)
    cipher_index = 0
    salt_index = 0
    for i in range(8, total_length):
        pos = i - 8
        if salt_index < salt_length and i == salt_positions[salt_index]:
            salt[salt_index] = intermediate[pos]
            salt_index += 1
        else:
            cipher_bytes[cipher_index] = intermediate[pos]
            cipher_index += 1

    # Regenerate keystream and decrypt the ciphertext.
    key_bytes = key.encode("utf-8")
    keystream = generate_keystream(key_bytes, bytes(salt), cipher_length)
    plaintext_bytes = bytes([c ^ k for c, k in zip(cipher_bytes, keystream)])
    return plaintext_bytes.decode("utf-8")


if __name__ == "__main__":
    # Example usage.
    text = "This is a test!"
    key = "this_is_a_key"
    
    for i in range(10):
        encrypted = encrypt(text, key)
        print(f"Encrypted #{i}: {encrypted}")
        decrypted = decrypt(encrypted, key)
        print("Decrypted:", decrypted)
