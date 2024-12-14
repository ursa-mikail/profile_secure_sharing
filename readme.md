# Profile Secure Sharing
This project demonstrates the use of AES-GCM-256 encryption for securing user profile data and HMAC (Hash-based Message Authentication Code) for verifying the integrity of the data before and after encryption.

## Overview

- **AES-GCM-256 Encryption**: Encrypts sensitive user data using AES encryption in Galois/Counter Mode (GCM).
- **HMAC**: Ensures data integrity by signing both the plaintext (before encryption) and the ciphertext (after encryption).
- **Scenario**: A user profile is created, encrypted, and shared with integrity verification at both stages (before and after encryption).

## Demo Breakdown

### demo_situation

- The program demonstrates how to encrypt a user profile and generate HMACs for verification.
- A user profile (e.g., `name`, `address`, `birth`, `occupation`, etc) is selected for encryption.
  
### demo_scenario

- The encryption process is handled using AES-GCM-256 with random IV and HMAC keys.
- The user profile is encrypted, and two HMAC values are generated:
  - **HMAC before encryption**: Used to verify the integrity of the plaintext data.
  - **HMAC after encryption**: Used to verify the integrity of the encrypted data.
  
### demo_scene

- The encrypted profile and HMAC values are displayed in hexadecimal format for both before and after encryption.
- HMAC verification is performed on the encrypted data to ensure it has not been tampered with.
  
### demo_case

- The program uses random AES and HMAC keys for encryption and verification.
- The user can simulate sharing their profile by selecting specific fields (e.g., `name`, `address`, etc) to include in the encrypted message.
  
The script will encrypt the profile, display HMAC values, and perform verification.

## Example Output

```json
{
    "encrypted_profile": "9f3f7c221ecd5748c7ba8bfc7b68c8d9b5d22c77b0b8468398b070d39aab836c040f3bc3b3127fb103b5c3f0808d6232a2c9f440cbf45dbb24fc6b90b1409350f",
    "hmac_before_cipher": "9d3f60b23a9b557c31e61dbdb7455b9de9ac6eeb0759fc31e2c570f78f04bfc0",
    "hmac_after_cipher": "a2a0f6c10f6483f1c9cb1d02ef60f25de4676070d0470d730bf5cd97a5d564dd"
}
