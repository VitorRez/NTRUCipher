from crypto.PBKDF import *
from crypto.ciphers import *
from Crypto.Random import get_random_bytes

msg = 'banana'
password = 'amobanana'
salt = get_random_bytes(16)
key = PBKDF(password, salt)
c = CipherHandler()