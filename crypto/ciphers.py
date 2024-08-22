from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import NtruCipher
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pickle

class CipherHandler:

    def __init__(self, aes_key, ntru_key):
        self.aes_key = aes_key
        self.ntru_key = ntru_key

    def encrypt_sym(self, msg):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        nonce = cipher.nonce
        if type(msg) == bytes:
            ciphertext, tag = cipher.encrypt_and_digest(msg)
        else:
            ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
        return (nonce, ciphertext)

    def decrypt_sym(self, nonce, ciphertext, key):
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        msg = cipher.decrypt(ciphertext)
        if type(msg) != bytes:
            msg = bytes.decode(msg)
        return msg
    
    def encrypt(self, msg):
        return encrypt(self.ntru_key, msg)
    
    def decrypt(self, enc_msg, ntru_key):
        return decrypt(ntru_key, enc_msg)
    
    def e_protocol(self, msg):
        enc = self.encrypt_sym(msg)
        enc_ntru = self.encrypt(self.aes_key)
        separator = b'-----'
        return enc[0] + separator + enc[1] + separator + pickle.dumps(enc_ntru)

    def d_protocol(self, enc_text, ntru_key):
        separator = b'-----'
        enc = enc_text.split(separator)
        aes_key = self.decrypt(pickle.loads(enc[2]), ntru_key)
        msg = self.decrypt_sym(enc[0], enc[1], aes_key)
        return msg