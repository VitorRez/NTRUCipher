from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from PyNTRU.ciphers import CipherHandler
from PyNTRU.ntru.hash import *
import pickle

#Password-Based Key Derivation Function
def PBKDF(password, salt):
    key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
    return key

def encrypt_pbkdf(key_ntru, password, salt):
    key_sym = PBKDF(password, salt)
    c = CipherHandler(key_sym, 0)
    enc_key = c.encrypt_sym(pickle.dumps(key_ntru))
    return enc_key

def decrypt_pbkdf(enc_key, password, salt):
    key_sym = PBKDF(password, salt)
    c = CipherHandler(aes_key=key_sym)
    key_ntru = c.decrypt_sym(enc_key[0], enc_key[1])
    return pickle.loads(key_ntru)

def verify_password(password, p_hash):
    p_hash1 = create_hash(password)
    if p_hash == p_hash1:
        return True
    else:
        return False