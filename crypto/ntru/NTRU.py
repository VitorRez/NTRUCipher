from crypto.ntru.ntrucipher import NtruCipher
from crypto.ntru.mathutils import random_poly
from sympy.abc import x
from sympy import ZZ, Poly
from crypto.padding.padding import padding_encode, padding_decode
from Crypto.Hash import SHA256
import numpy as np
import math

def generate(N, p, q, Dmin, Dmax):
    ntru = NtruCipher(N, p, q, Dmin, Dmax)
    ntru.generate_random_keys()
    
    g = np.array(ntru.g_poly.all_coeffs()[::-1])
    h = np.array(ntru.h_poly.all_coeffs()[::-1])
    f = np.array(ntru.f_poly.all_coeffs()[::-1])
    f_p = np.array(ntru.f_p_poly.all_coeffs()[::-1])
    
    priv_key = {'N': N, 'p': p, 'q': q, 'f': f, 'f_p': f_p, 'g': g, 'Dmin': Dmin, 'Dmax': Dmax}
    pub_key = {'N': N, 'p': p, 'q': q, 'h': h, 'Dmin': Dmin, 'Dmax': Dmax}
    
    return priv_key, pub_key

def encrypt(pub_key, input_str):

    input_arr = np.unpackbits(np.frombuffer(input_str, dtype=np.uint8))

    ntru = NtruCipher(int(pub_key['N']), int(pub_key['p']), int(pub_key['q']), int(pub_key['Dmin']), int(pub_key['Dmax']))
    ntru.h_poly = Poly(pub_key['h'].astype(int)[::-1], x).set_domain(ZZ)

    if ntru.N < len(input_arr):
        raise Exception("Input is too large for current N")
    
    output = (ntru.encrypt(Poly(input_arr[::-1], x).set_domain(ZZ),random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])

    return output

def decrypt(priv_key, input):

    input_arr = np.array(input).flatten()

    ntru = NtruCipher(int(priv_key['N']), int(priv_key['p']), int(priv_key['q']), int(priv_key['Dmin']), int(priv_key['Dmax']))
    ntru.f_poly = Poly(priv_key['f'].astype(int)[::-1], x).set_domain(ZZ)
    ntru.f_p_poly = Poly(priv_key['f_p'].astype(int)[::-1], x).set_domain(ZZ)

    if ntru.N < len(input_arr):
        raise Exception("Input is too large for current N")
    
    decrypted = ntru.decrypt(Poly(input_arr[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]

    return(np.packbits(np.array(decrypted).astype(int)).tobytes())

def sign(priv_key, input_str):

    input_arr = np.unpackbits(np.frombuffer(input_str, dtype=np.uint8))

    ntru = NtruCipher(int(priv_key['N']), int(priv_key['p']), int(priv_key['q']), int(priv_key['Dmin']), int(priv_key['Dmax']))
    ntru.f_poly = Poly(priv_key['f'].astype(int)[::-1], x).set_domain(ZZ)
    ntru.f_p_poly = Poly(priv_key['f_p'].astype(int)[::-1], x).set_domain(ZZ)
    ntru.g_poly = Poly(priv_key['g'].astype(int)[::-1], x).set_domain(ZZ)

    if ntru.N < len(input_arr):
        raise Exception("Input is too large for current N")
    
    try:
        m_poly, s = ntru.sign(input_arr)
        return m_poly, s
    except:
        print("couldn't sign")

def verify(pub_key, m_poly, s):

    ntru = NtruCipher(int(pub_key['N']), int(pub_key['p']), int(pub_key['q']), int(pub_key['Dmin']), int(pub_key['Dmax']))
    ntru.h_poly = Poly(pub_key['h'].astype(int)[::-1], x).set_domain(ZZ)
    
    return ntru.verify(m_poly, s)
    

