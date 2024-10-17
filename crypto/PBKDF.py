from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from crypto.ciphers import CipherHandler

def PBKDF(password, salt):
    key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
    return key

def encrypt_pbkdf(key_ntru, password, salt):
    key_sym = PBKDF(password, salt)
    c = CipherHandler(0, key_sym)
    enc_key = c.encrypt_sym(key_ntru)
    return enc_key

def decrypt_pbkdf(nonce, enc_key, password, salt):
    key_sym = PBKDF(password, salt)
    c = CipherHandler(0, key_sym)
    key_ntru = c.decrypt_sym(nonce, enc_key, key_sym)
    return key_ntru

def verify_password(password, p_hash):
    p_hash1 = SHA256.new(bytes(password,'utf-8'))
    if p_hash == p_hash1:
        return True
    else:
        return False