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

def main():
    file_json = './sample_data/data/profile_00.json'
    with open(file_json, 'r') as file:
        profile = json.load(file)
        
    print("Profile Sharing")
    selected_fields = {}

    for field in profile:
        selected_fields[field] = input(f"Do you want to share {field}? (yes/no): ").strip().lower() == 'yes'

    fields_to_share = {field: profile[field] for field, selected in selected_fields.items() if selected}

    if not fields_to_share:
        print("No fields selected to share.")
        return

    shared_profile_json = json.dumps(fields_to_share)
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
Profile Sharing
Do you want to share name? (yes/no): yes
Do you want to share address? (yes/no): no
Do you want to share birth? (yes/no): yes
Do you want to share occupation? (yes/no): no
Encrypted Shared Profile:
Hexadecimal Representation:
238de35075e4a724fd96c3b8204f267473eaa3bbf35f2509d26e56631bb300b9b1129f630e9946cdc618fcb20f1f322113007447dcdbf32a645b0b7175e0a5c026138f58496beae3f6800f5442ca7e4e21213ddde053577ae4ed91b2c28eac64b439af7ca3616f
HMAC (Before Encryption):
Hexadecimal Representation:
eba6ad2f84f0b4d8db3b77d8bc454323a40c0af5e1547f43673f69a862bfa687

Decrypted Profile:
Indented JSON:
{
    "name": "John Doe",
    "birth": "1990-01-01"
}
"""