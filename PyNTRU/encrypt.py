from PyNTRU.ntru.NTRU import *
from PyNTRU.encrypt_sym import *
import pickle

#class used to encrypt and decrypt messages using a key encapsulation mechanism
class Encrypt:

    def __init__(self, ntru_key):
        self.aes_key = get_random_bytes(16)
        self.ntru_key = ntru_key

    #encrypt message with an AES key
    def encrypt_sym(self, msg):
        return encrypt_sym(self.aes_key, msg)

    #decrypt message with an AES key
    def decrypt_sym(self, ciphertext):
        return decrypt_sym(self.aes_key, ciphertext)
    
    #encrypt message with a NTRU public key
    def encrypt(self, msg):
        return encrypt(self.ntru_key, msg)
    
    #decrypt message with a NTRU private key
    def decrypt(self, enc_msg, ntru_key):
        return decrypt(ntru_key, enc_msg)
    
    #encryption protocol using a key encapsulation mechanism
    def e_protocol(self, msg):
        enc = self.encrypt_sym(msg)
        enc_ntru = self.encrypt(self.aes_key)
        separator = b'-----'
        return enc[0] + separator + enc[1] + separator + pickle.dumps(enc_ntru)

    #decryption protocol using a key encapsulation mechanism
    def d_protocol(self, enc_text):
        separator = b'-----'
        enc = enc_text.split(separator)
        self.aes_key = self.decrypt(pickle.loads(enc[2]), self.ntru_key)
        msg = self.decrypt_sym(enc)
        return msg