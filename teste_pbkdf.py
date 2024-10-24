from crypto.PBKDF import *
from crypto.ciphers import *
from crypto.hash import *
from Crypto.Random import get_random_bytes

msg = "banana"
password = "amobanana"

#encrypt

priv_key_ntru, pub_key_ntru = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)
aes_key = get_random_bytes(16)

c_enc = CipherHandler(aes_key, pub_key_ntru)

salt = get_random_bytes(16)
pbkdf_key = PBKDF(password, salt)
password_hash = create_hash(password)

enc_key = encrypt_pbkdf(priv_key_ntru, password, salt)

enc_msg = c_enc.e_protocol(msg)

#decrypt

if verify_password('amobanana', password_hash):
    priv_key = decrypt_pbkdf(enc_key, 'amobanana', salt)
    d_enc = CipherHandler(ntru_key=priv_key)
    clear_msg = d_enc.d_protocol(enc_msg)
    print(clear_msg)
else:
    print("Invalid password.")
