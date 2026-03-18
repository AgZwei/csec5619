import json
import binascii
from nacl.public import PrivateKey

def generate_key_pair():
    """Generates an X25519 key pair and returns them as hex strings."""
    priv_key = PrivateKey.generate()
    pub_key = priv_key.public_key
    
    return {
        "priv": binascii.hexlify(bytes(priv_key)).decode('utf-8'),
        "pub": binascii.hexlify(bytes(pub_key)).decode('utf-8')
    }

def create_client_bundle(name):
    """Generates the X3DH key bundle for a client."""
    print(f"Generating keys for {name}...")
    
    # 1. Identity Key (Long-term)
    identity_key = generate_key_pair()
    
    # 2. Signed Pre-Key (Medium-term, rotated occasionally)
    # Note: In a full implementation, this public key would be digitally 
    # signed by the Identity Private Key using Ed25519 to prevent tampering.
    signed_pre_key = generate_key_pair()
    
    # 3. One-Time Pre-Keys (Single use, consumed when someone messages you)
    one_time_pre_keys = {
        "opk_1": generate_key_pair(),
        "opk_2": generate_key_pair(),
        "opk_3": generate_key_pair()
    }
    
    client_data = {
        "identity_key": identity_key,
        "signed_pre_key": signed_pre_key,
        "one_time_pre_keys": one_time_pre_keys
    }
    
    # Save to a local JSON file
    filename = f"{name.lower()}_keys.json"
    with open(filename, 'w') as f:
        json.dump(client_data, f, indent=4)
    print(f"   [Success] Saved {name}'s keys to {filename}\n")

if __name__ == "__main__":
    create_client_bundle("Alice")
    create_client_bundle("Bob")