import json
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


def display_hex_str(byte_str):
    """Convert byte string to hexadecimal representation."""
    hex_str = byte_str.hex()
    print(f"Hexadecimal Representation:\n{hex_str}")
    return hex_str

def indent_display_json(json_str):
    """Display a JSON string in an indented format."""
    json_obj = json.loads(json_str)
    pretty_json = json.dumps(json_obj, indent=4)
    print(f"Indented JSON:\n{pretty_json}")
    return pretty_json


# AES-GCM-256 Key and HMAC Keys
aes_key = os.urandom(32)
hmac_key_before = os.urandom(16)
hmac_key_after = os.urandom(16)

# Function to encrypt and HMAC a message
def encrypt_and_hmac(data, aes_key, hmac_key_before, hmac_key_after):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    encrypted_data = iv + encryptor.tag + ciphertext

    # HMAC before encryption
    hmac_before = HMAC(hmac_key_before, hashes.SHA256(), backend=default_backend())
    hmac_before.update(data.encode())
    hmac_before_value = hmac_before.finalize()

    # HMAC after encryption
    hmac_after = HMAC(hmac_key_after, hashes.SHA256(), backend=default_backend())
    hmac_after.update(encrypted_data)
    hmac_after_value = hmac_after.finalize()

    return encrypted_data + hmac_after_value, hmac_before_value

# Function to decrypt and verify HMAC
def decrypt_and_verify(encrypted_data, aes_key, hmac_key_before, hmac_key_after, hmac_before_value):
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:-32]
    hmac_after_value = encrypted_data[-32:]

    # Verify HMAC after encryption
    hmac_after = HMAC(hmac_key_after, hashes.SHA256(), backend=default_backend())
    hmac_after.update(encrypted_data[:-32])
    hmac_after.verify(hmac_after_value)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Verify HMAC before encryption
    hmac_before = HMAC(hmac_key_before, hashes.SHA256(), backend=default_backend())
    hmac_before.update(decrypted_data)
    hmac_before.verify(hmac_before_value)

    return decrypted_data.decode()

# Usage
file_json = './sample_data/data/profile_00.json'
with open(file_json, 'r') as file:
    profile = json.load(file)

# User selects fields to share
fields_to_share = ["name", "address"]  # Example: selected by user

shared_profile = {field: profile[field] for field in fields_to_share}
shared_profile_json = json.dumps(shared_profile)

# Encrypt and HMAC the shared profile
encrypted_shared_profile, hmac_before_value = encrypt_and_hmac(shared_profile_json, aes_key, hmac_key_before, hmac_key_after)

# Print the encrypted shared profile and HMAC
print("Encrypted Shared Profile:")
display_hex_str(encrypted_shared_profile)
print("HMAC (Before Encryption):")
display_hex_str(hmac_before_value)


# Decrypt and verify the shared profile
decrypted_shared_profile = decrypt_and_verify(encrypted_shared_profile, aes_key, hmac_key_before, hmac_key_after, hmac_before_value)

# Print the decrypted shared profile
print("Decrypted Shared Profile:")
indent_display_json(decrypted_shared_profile)

"""
Encrypted Shared Profile:
Hexadecimal Representation:
f266d0d4fc1a6099ad7ed9eb84fc3448914aaccbb4cd439046a85014aedc7428ac150e2150f2e529cda46476c0130bfe5c33413deaa4f66426021aedda4591e97e19dd4e2f12102fbc5bf845741b78aac0286d13517e2e66c8b01454346048877596bc22fb6a61a91466272a37801fd16a05353f648b5b0324
HMAC (Before Encryption):
Hexadecimal Representation:
b847ba8e940ca137980e7672fa3c215a41fac3077a0f684444e80a19558f9185
Decrypted Shared Profile:
Indented JSON:
{
    "name": "John Doe",
    "address": "1234 Main St, Anytown, USA"
}
{\n    "name": "John Doe",\n    "address": "1234 Main St, Anytown, USA"\n}
"""