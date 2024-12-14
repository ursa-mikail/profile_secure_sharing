import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# AES-GCM-256 Key and HMAC Keys
aes_key = os.urandom(32)
hmac_key_before = os.urandom(16)
hmac_key_after = os.urandom(16)

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

def display_menu(options):
    selected = {option: False for option in options}

    print("Select the fields to share (enter numbers separated by commas):")
    for idx, option in enumerate(options):
        print(f"{idx + 1}. {option}")

    choice = input("Your choice: ").split(',')
    for idx in choice:
        if idx.strip().isdigit() and 1 <= int(idx.strip()) <= len(options):
            selected[options[int(idx.strip()) - 1]] = True

    return selected

def main():
    file_json = './sample_data/data/profile_00.json'
    with open(file_json, 'r') as file:
        profile = json.load(file)

    fields = list(profile.keys())
    selected_fields = display_menu(fields)

    shared_fields = {field: profile[field] for field in fields if selected_fields[field]}

    if not shared_fields:
        print("No fields selected to share.")
        return

    shared_profile_json = json.dumps(shared_fields)
    encrypted_shared_profile, hmac_before_value = encrypt_and_hmac(shared_profile_json, aes_key, hmac_key_before, hmac_key_after)

    # Print the encrypted shared profile and HMAC
    print("Encrypted Shared Profile:")
    display_hex_str(encrypted_shared_profile)
    print("HMAC (Before Encryption):")
    display_hex_str(hmac_before_value)

    # For demonstration, decrypt and verify
    try:
        decrypted_profile = decrypt_and_verify(encrypted_shared_profile, aes_key, hmac_key_before, hmac_key_after, hmac_before_value)
        print("\nDecrypted Profile:")
        indent_display_json(decrypted_profile)

    except Exception as e:
        print("Decryption or HMAC verification failed:", e)

if __name__ == "__main__":
    main()

"""
Select the fields to share (enter numbers separated by commas):
1. name
2. address
3. birth
4. occupation
Your choice: 1,2,4
Encrypted Shared Profile:
Hexadecimal Representation:
8f7fbc304b3c4fd795aa5670fa78c95bd7809ad95ef87c2168708b343f0f3e8869ab6913423ab7a7be38bfa6ba69dba33fe11752903fb90acce5707cb2c176729856129975bc819060258a4a377ac14f3ec3d1295a13fc4cbb5bec48c17c959b5a463b59a50e74bdb705bb51f2ca53e62ebed4274499641e21184de4eccf650eaa5b90591e952c01f8f0412d7d3a4568d27bee833f07c382a7b68e56
HMAC (Before Encryption):
Hexadecimal Representation:
23861691c7c482542ed51d80deffdc7679d2a0dba3c0daa3838e3608b1764969

Decrypted Profile:
Indented JSON:
{
    "name": "John Doe",
    "address": "1234 Main St, Anytown, USA",
    "occupation": "Software Engineer"
}
"""