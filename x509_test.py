from PyNTRU.PBKDF import *
from PyNTRU.ciphers import *
from PyNTRU.ntru.hash import *
from PyNTRU.certificate import *

priv_key_auth, pub_key_auth = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

signature = Signature(priv_key_auth, pub_key_auth)

priv_key, pub_key = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)
pub_key_pem = export_key(pub_key)

m, s = request(0, 'client', pub_key_pem, signature)
cert = create_certificate('auth', 'client', pub_key_pem, 'BR', 'client', '', s)

pub_key_new = get_pub_key('certificate_client.pem')

if pub_key_new == pub_key:
    print('boa')