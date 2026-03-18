import binascii
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

def main():
    # =========================================================
    # PART 1: Generate Valid Ed25519 Keys & Save
    # =========================================================
    print("1. Generating valid Ed25519 signing key pair...")
    
    # Generate a real SigningKey (Private) and derive the VerifyKey (Public)
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    # Save to text files as hex strings
    priv_hex = binascii.hexlify(bytes(signing_key)).decode('utf-8')
    pub_hex = binascii.hexlify(bytes(verify_key)).decode('utf-8')

    with open("sign_priv.txt", "w") as f: f.write(priv_hex)
    with open("sign_pub.txt", "w") as f: f.write(pub_hex)
        
    print("   [Success] Saved to sign_priv.txt and sign_pub.txt\n")

    # =========================================================
    # PART 2: Read Keys from Files
    # =========================================================
    print("2. Loading keys from files...")
    
    with open("sign_priv.txt", "r") as f: loaded_priv_hex = f.read().strip()
    with open("sign_pub.txt", "r") as f: loaded_pub_hex = f.read().strip()

    # Rebuild the PyNaCl objects from the hex strings
    loaded_signing_key = SigningKey(bytes.fromhex(loaded_priv_hex))
    loaded_verify_key = VerifyKey(bytes.fromhex(loaded_pub_hex))

    # =========================================================
    # PART 3: Sign a Message
    # =========================================================
    message = b"Transfer $100 to account ABC."
    print(f"3. Original Message: '{message.decode('utf-8')}'")

    # The sign() method generates a signature and attaches it to the message
    signed_message = loaded_signing_key.sign(message)
    
    # Let's look at just the signature portion
    print(f"   Digital Signature (Hex): {binascii.hexlify(signed_message.signature).decode('utf-8')[:50]}...\n")

    # =========================================================
    # PART 4: Verify the Message
    # =========================================================
    print("4. Verifying the signature with the Public Key...")
    try:
        # The verify() method checks the math. If valid, it strips the signature 
        # and returns the original message. If invalid, it throws an error.
        verified_message = loaded_verify_key.verify(signed_message)
        print(f"   [Success] Signature is VALID! Proved message: '{verified_message.decode('utf-8')}'\n")
    except BadSignatureError:
        print("   [Error] Signature verification failed!\n")

    # =========================================================
    # PART 5: The Tamper Test (What if a hacker intercepts it?)
    # =========================================================
    print("5. Tamper Test: A hacker changes the message in transit...")
    
    # Hacker intercepts the message and changes the amount to $900
    forged_message = b"Transfer $900 to account ABC."
    
    # Hacker attaches your original signature to their forged message
    forged_payload = signed_message.signature + forged_message

    try:
        # The receiving server tries to verify it with your public key
        loaded_verify_key.verify(forged_payload)
        print("   [Danger] The forged message was accepted!")
    except BadSignatureError:
        print("   [Success - Forgery Blocked] BadSignatureError caught!")
        print("   The Public Key detected that the message doesn't match the signature.")

if __name__ == "__main__":
    main()