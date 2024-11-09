from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from PyNTRU.encrypt import Encrypt
from PyNTRU.encrypt_sym import *
from PyNTRU.ntru.hash import create_hash, verify_hash
import pickle

#Password-Based Key Derivation Function
def PBKDF(password, salt=None):
    if salt == None:
        salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
    p_hash = create_hash(password)
    return {'key': key, 'salt': salt, 'p_hash': p_hash}

def encrypt_pbkdf(key_pbkdf, key_ntru):
    enc_key = encrypt_sym(key_pbkdf['key'], pickle.dumps(key_ntru))
    return enc_key

def decrypt_pbkdf(password, key_pbkdf, enc_key):
    p_hash1 = create_hash(password)
    if key_pbkdf['p_hash'] == p_hash1:
        key_ntru = decrypt_sym(key_pbkdf['key'], enc_key)
        return pickle.loads(key_ntru)
    else:
        return None