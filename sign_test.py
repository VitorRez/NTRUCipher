from PyNTRU.ciphers import *
from PyNTRU.ntru.NTRU import *
from PyNTRU.ntru.ntrucipher import *
from PyNTRU.ntru.ntrusign import *

priv_key, pub_key = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)
p1, p2 = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

msg = b'bananaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

m_poly, s1 = sign(priv_key, pub_key, msg)

print(m_poly, s1)

tries = 1
while not verify(p2, m_poly, s1):
    print(f'invalid signature {tries}')
    tries += 1
    p1, p2 = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

if verify(pub_key, m_poly, s1):
    print('valid signature')
else:
    print('invalid signature')