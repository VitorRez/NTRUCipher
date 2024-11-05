from crypto.ciphers import *
from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import *

priv_key, pub_key = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

print(priv_key)
print()
print(pub_key)
print()

ku = import_public_key(pub_key)
kr = import_private_key(priv_key)

print(kr)
print()
print(ku)
print()
