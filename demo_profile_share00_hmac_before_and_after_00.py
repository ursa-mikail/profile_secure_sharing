import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac

def generate_hmac(key, data):
    """Generate HMAC for given data using a consistent method."""
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def encrypt_profile(profile_data, aes_key, hmac_key_before, hmac_key_after):
    """Encrypt profile with pre and post encryption HMACs."""
    # Ensure consistent JSON formatting
    clean_data = json.dumps(profile_data, separators=(',', ':'), sort_keys=True)

    # HMAC before encryption
    hmac_before = generate_hmac(hmac_key_before, clean_data.encode())

    # Encrypt using AES-GCM
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt clean data
    ciphertext = encryptor.update(clean_data.encode()) + encryptor.finalize()

    # Combine encryption components
    encrypted_part = iv + encryptor.tag + ciphertext

    # HMAC after encryption
    hmac_after = generate_hmac(hmac_key_after, encrypted_part)

    # Final encrypted payload
    final_encrypted_data = encrypted_part + hmac_before + hmac_after

    return {
        "profile": profile_data,
        "encrypted_profile": final_encrypted_data.hex(),
        "hmac_before_cipher": hmac_before.hex(),
        "hmac_after_cipher": hmac_after.hex()
    }

def decrypt_profile(encrypted_payload, aes_key, hmac_key_before, hmac_key_after):
    """Decrypt profile with comprehensive HMAC verification."""
    # Convert hex strings back to bytes
    encrypted_data = bytes.fromhex(encrypted_payload['encrypted_profile'])

    # Separate encrypted data components
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:-64]
    original_hmac_before = encrypted_data[-64:-32]
    received_hmac_after = encrypted_data[-32:]

    # Verify HMAC after encryption
    encrypted_part = encrypted_data[:12+16+len(ciphertext)]
    try:
        # Recreate HMAC verification
        h_after = hmac.HMAC(hmac_key_after, hashes.SHA256(), backend=default_backend())
        h_after.update(encrypted_part)
        h_after.verify(received_hmac_after)
        print("Post-encryption HMAC verification successful.")
    except Exception as e:
        print(f"HMAC After verification failed: {e}")
        raise

    # Decrypt the data
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Verify HMAC before encryption
    try:
        h_before = hmac.HMAC(hmac_key_before, hashes.SHA256(), backend=default_backend())
        h_before.update(decrypted_data)
        h_before.verify(original_hmac_before)
        print("Pre-encryption HMAC verification successful.")
    except Exception as e:
        print(f"HMAC Before verification failed: {e}")
        raise

    return json.loads(decrypted_data.decode())

def main():
    # Sample user profile
    """
    profile = {
        "name": "John Doe",
        "address": "1234 Main St, Anytown, USA",
        "birth": "1990-01-01",
        "occupation": "Software Engineer"
    }
    """
    file_json = './sample_data/data/profile_00.json'

    with open(file_json, 'r') as file:
        profile = json.load(file)

    # Example: printing the profile to verify
    print(profile)

    # Generate keys
    aes_key = os.urandom(32)
    hmac_key_before = os.urandom(32)
    hmac_key_after = os.urandom(32)

    # Encrypt profile
    encrypted_payload = encrypt_profile(profile, aes_key, hmac_key_before, hmac_key_after)
    print("\nEncrypted Payload:")
    print(json.dumps(encrypted_payload, indent=2))

    # Decrypt profile
    decrypted_profile = decrypt_profile(encrypted_payload, aes_key, hmac_key_before, hmac_key_after)
    print("\nDecrypted Profile:")
    print(json.dumps(decrypted_profile, indent=2))

if __name__ == "__main__":
    main()

"""
{'name': 'John Doe', 'address': '1234 Main St, Anytown, USA', 'birth': '1990-01-01', 'occupation': 'Software Engineer'}

Encrypted Payload:
{
  "profile": {
    "name": "John Doe",
    "address": "1234 Main St, Anytown, USA",
    "birth": "1990-01-01",
    "occupation": "Software Engineer"
  },
  "encrypted_profile": "114a9e78786286cf1ab9af84d643ea9d27068eec8cb4345e64e91cdf2a6ffb5798abf24dc4e47e390fb0a66815bd989e8e190e740b69a85f52b12df0dbbfdfc095e18538e2ff4a86f40dce8c2775649d4330901df2d05064d34eab4e72bd175e8717467eb6e3c6f5e987bc40a62386020c566219e697e29e6b25da91316818afde9bf9da6993e0369ebf370317b3684fb66a5eb788c037c49714748ec2f54a7b869cc5e054dc01786df3f02c53e2f6377527981ab7831439d7c8e1463d834310c35263040423b21ccdff9622",
  "hmac_before_cipher": "17b3684fb66a5eb788c037c49714748ec2f54a7b869cc5e054dc01786df3f02c",
  "hmac_after_cipher": "53e2f6377527981ab7831439d7c8e1463d834310c35263040423b21ccdff9622"
}
Post-encryption HMAC verification successful.
Pre-encryption HMAC verification successful.

Decrypted Profile:
{
  "address": "1234 Main St, Anytown, USA",
  "birth": "1990-01-01",
  "name": "John Doe",
  "occupation": "Software Engineer"
}
"""