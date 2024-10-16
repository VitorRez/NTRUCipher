from crypto.ciphers import *
from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import *
from crypto.ntru.ntrusign import *

priv_key, pub_key = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)
p1, p2 = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

msg = b'banana'

m_poly, s1 = sign(priv_key, pub_key, msg)

#print(m_poly.all_coeffs(), s1.all_coeffs())

#tries = 1
#while not verify(p2, m_poly, s1):
#    print(f'invalid signature {tries}')
#    tries += 1
#    p1, p2 = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

if verify(pub_key, m_poly, s1):
    print('valid signature')
else:
    print('invalid signature')