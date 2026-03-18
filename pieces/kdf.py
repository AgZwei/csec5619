import hashlib
import os
import binascii

def generate_derived_key(password: str, salt: bytes = None, iterations: int = 600_000) -> dict:
    """
    Derives a secure cryptographic key from a password using PBKDF2 with HMAC-SHA256.
    
    Args:
        password: The secret password or passphrase to derive the key from.
        salt: A random value to protect against rainbow table attacks. Generated if None.
        iterations: The number of hashing iterations. Higher = more secure, but slower.
                    (600,000 is a modern recommendation for PBKDF2-HMAC-SHA256).
                    
    Returns:
        A dictionary containing the derived key and the salt used (both as hex strings).
    """
    # 1. Generate a random 16-byte salt if one is not provided
    if salt is None:
        salt = os.urandom(16)
        
    # 2. Encode the password to bytes
    password_bytes = password.encode('utf-8')
    
    # 3. Derive the key using PBKDF2 HMAC-SHA256
    # We are requesting a 32-byte (256-bit) key, which is standard for algorithms like AES-256
    derived_key_bytes = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password_bytes,
        salt=salt,
        iterations=iterations,
        dklen=32 
    )
    
    # 4. Return the hex representation of the key and salt for easy storage/display
    return {
        "key_hex": binascii.hexlify(derived_key_bytes).decode('utf-8'),
        "salt_hex": binascii.hexlify(salt).decode('utf-8'),
        "iterations": iterations
    }

# --- Example Usage ---
if __name__ == "__main__":
    my_password = "correct_horse_battery_staple_123!"
    
    print("Deriving key... (this may take a fraction of a second due to the iterations)")
    result = generate_derived_key(my_password)
    
    print("\n--- Key Derivation Complete ---")
    print(f"Original Password: {my_password}")
    print(f"Salt (Save this to recreate the key): {result['salt_hex']}")
    print(f"Derived 256-bit Key: {result['key_hex']}")
    print(f"Iterations: {result['iterations']}")