from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_sym(aes_key, msg):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher.nonce
    if type(msg) == bytes:
        ciphertext, tag = cipher.encrypt_and_digest(msg)
    else:
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
    return nonce, ciphertext

def decrypt_sym(aes_key, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_EAX, ciphertext[0])
    msg = cipher.decrypt(ciphertext[1])
    if type(msg) != bytes:
        msg = bytes.decode(msg)
    return msg
