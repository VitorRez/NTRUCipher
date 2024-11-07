from PyNTRU.ntru.NTRU import *
from PyNTRU.ntru.ntrucipher import NtruCipher
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pickle

#class used to encrypt and decrypt messages using a key encapsulation mechanism
class CipherHandler:

    def __init__(self, aes_key=0, ntru_key=0):
        self.aes_key = aes_key
        self.ntru_key = ntru_key

    #encrypt message with an AES key
    def encrypt_sym(self, msg):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        nonce = cipher.nonce
        if type(msg) == bytes:
            ciphertext, tag = cipher.encrypt_and_digest(msg)
        else:
            ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
        return (nonce, ciphertext)

    #decrypt message with an AES key
    def decrypt_sym(self, nonce, ciphertext):
        cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce)
        msg = cipher.decrypt(ciphertext)
        if type(msg) != bytes:
            msg = bytes.decode(msg)
        return msg
    
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
        msg = self.decrypt_sym(enc[0], enc[1])
        return msg