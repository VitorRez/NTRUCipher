from PyNTRU.ciphers import *
from PyNTRU.ntru.NTRU import *
from PyNTRU.ntru.ntrucipher import *

priv_key, pub_key = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

priv_key_pem = export_key(priv_key, 'private')
pub_key_pem = export_key(pub_key)

priv_key_new = import_key(priv_key_pem, 'private')
pub_key_new = import_key(pub_key_pem)

if priv_key != priv_key_new:
    print('deu ruim priv')
elif pub_key != pub_key_new:
    print('deu ruim pub')
else:
    print('deu bom')