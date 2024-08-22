from crypto.ciphers import *
from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import *

priv_key_ntru, pub_key_ntru = generate(N=251, p=3, q=128)
aes_key = get_random_bytes(16)

msg = b'banana'

e = CipherHandler(aes_key, pub_key_ntru)
enc_text = e.e_protocol(msg)
print(enc_text)

plaintext = e.d_protocol(enc_text, priv_key_ntru)
print(plaintext)