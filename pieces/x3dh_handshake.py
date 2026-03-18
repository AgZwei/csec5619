import json
import binascii
import hashlib
from nacl.public import PrivateKey, PublicKey

def load_keys(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def get_priv(key_dict):
    return PrivateKey(bytes.fromhex(key_dict["priv"]))

def get_pub(key_dict):
    return PublicKey(bytes.fromhex(key_dict["pub"]))

def main():
    print("--- Starting X3DH Handshake ---\n")
    
    # 1. Load local key stores
    alice_store = load_keys("alice_keys.json")
    bob_store = load_keys("bob_keys.json")
    
    # ====================================================================
    # ALICE'S PERSPECTIVE: Generating the Shared Secret
    # ====================================================================
    print("1. Alice is initiating the conversation with Bob.")
    
    # Alice loads her long-term Identity Key
    alice_IK_priv = get_priv(alice_store["identity_key"])
    
    # Alice generates a temporary Ephemeral Key just for this session
    alice_EK_priv = PrivateKey.generate()
    alice_EK_pub = alice_EK_priv.public_key
    
    # Alice fetches Bob's public keys from the "server"
    bob_IK_pub = get_pub(bob_store["identity_key"])
    bob_SPK_pub = get_pub(bob_store["signed_pre_key"])
    # She claims one of Bob's One-Time Pre-Keys
    bob_OPK_pub = get_pub(bob_store["one_time_pre_keys"]["opk_1"])
    
    # The X3DH Math: 4 Diffie-Hellman exchanges
    # exchange() securely computes a shared secret between a private and public key
    dh1 = alice_IK_priv.exchange(bob_SPK_pub)
    dh2 = alice_EK_priv.exchange(bob_IK_pub)
    dh3 = alice_EK_priv.exchange(bob_SPK_pub)
    dh4 = alice_EK_priv.exchange(bob_OPK_pub)
    
    # Alice combines them all and passes them through a Key Derivation Function (KDF)
    # We use SHA-256 here for simplicity, real Signal uses HKDF
    alice_shared_material = dh1 + dh2 + dh3 + dh4
    alice_shared_secret = hashlib.sha256(alice_shared_material).digest()
    
    print(f"   Alice's Calculated Shared Secret: {binascii.hexlify(alice_shared_secret).decode()[:30]}...")

    # ====================================================================
    # THE NETWORK: Alice sends her public info to Bob
    # ====================================================================
    # To allow Bob to calculate the same secret, Alice sends her Public Identity Key, 
    # her Public Ephemeral Key, and tells him which OPK she used.
    
    # ====================================================================
    # BOB'S PERSPECTIVE: Receiving and Calculating
    # ====================================================================
    print("\n2. Bob receives Alice's initial message and calculates his side.")
    
    # Bob loads his own Private Keys
    bob_IK_priv = get_priv(bob_store["identity_key"])
    bob_SPK_priv = get_priv(bob_store["signed_pre_key"])
    bob_OPK_priv = get_priv(bob_store["one_time_pre_keys"]["opk_1"])
    
    # Bob takes Alice's public keys that were sent over the network
    alice_IK_pub = get_pub(alice_store["identity_key"])
    
    # Bob performs the exact mirrored Diffie-Hellman math!
    # Notice how the Private/Public pairings are flipped compared to Alice.
    dh1_bob = bob_SPK_priv.exchange(alice_IK_pub)
    dh2_bob = bob_IK_priv.exchange(alice_EK_pub)
    dh3_bob = bob_SPK_priv.exchange(alice_EK_pub)
    dh4_bob = bob_OPK_priv.exchange(alice_EK_pub)
    
    # Bob combines them using the exact same KDF
    bob_shared_material = dh1_bob + dh2_bob + dh3_bob + dh4_bob
    bob_shared_secret = hashlib.sha256(bob_shared_material).digest()
    
    print(f"   Bob's Calculated Shared Secret:   {binascii.hexlify(bob_shared_secret).decode()[:30]}...")
    
    # ====================================================================
    # VERIFICATION
    # ====================================================================
    print("\n--- Handshake Complete ---")
    if alice_shared_secret == bob_shared_secret:
        print("[SUCCESS] Both parties derived the exact same secret key independently!")
        print("They can now use this key to encrypt messages using AES-256 or ChaCha20.")
    else:
        print("[FAILED] The keys do not match.")

if __name__ == "__main__":
    main()