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

def display_hex_str(data):
    print("".join(f"{byte:02x}" for byte in data))

def indent_display_json(data):
    parsed_json = json.loads(data)
    print(json.dumps(parsed_json, indent=4))

def main():
    files_json = ['./sample_data/data/profile_00.json', './sample_data/data/profile_01.json', './sample_data/data/profile_02.json']
    file_json = files_json[1]
    
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
5. contact
6. education
7. experience
8. skills
9. certifications
10. languages
11. hobbies
Your choice: 8, 9
Encrypted Shared Profile:
411901126bb2e8aa0dc9f3797c983e5790ac1e4b5c754f84b3e839902ce1c2e4b8811a13b86793f83958de41f33a047c7fd1a2e92cab0ade22834b23e8330ce3d32ef0be6a16021e278a23d51ef470190c577e7ddc21b23bd78582da6028235f291a171496f4a12dd97cd457a2d0df4f446af361f00bee258b3ed089ec991a63241c32d3150da1784a3874efd9c09b5ac610e84125ea468fc2e4d476d59f1e84b0a1c31c25f74d589f61586ccfd0e56f85eb557ad65085d2f5b535d90fbfc0eacede1a9d353cd5cf79670d7689223086e98dc99f98b8cfdb495e453ba46969fd900f4c97d51e630311910c6c8cb40f9363267a8fdc3b5336592161f4f021bd3179512d1ae5b2cbb650e0f86096905151ba063759f2628f47cfc4d250adf27399309a7e893a54567b870159522c960f6a42c8461b
HMAC (Before Encryption):
888fd0979cdf31cfb6eee7be1852a949233e0ae1b91ca900ef1849809435c2e4

Decrypted Profile:
{
    "skills": [
        "JavaScript",
        "React",
        "Node.js",
        "Python",
        "Django",
        "Docker",
        "Kubernetes",
        "AWS",
        "CI/CD",
        "Agile methodologies"
    ],
    "certifications": [
        {
            "name": "AWS Certified Solutions Architect",
            "issuer": "Amazon Web Services",
            "date": "2020-05"
        }
    ]
}
"""