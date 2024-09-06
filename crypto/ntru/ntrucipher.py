from crypto.ntru.mathutils import *
import numpy as np
from sympy.abc import x
from sympy.polys.polyerrors import NotInvertible
from sympy import ZZ, Poly
from scipy.stats import norm
from Crypto.Hash import SHA256
from random import choice
import hashlib

class NtruCipher:
    N = None
    p = None
    q = None

    f_poly = None
    g_poly = None
    h_poly = None

    f_p_poly = None
    f_q_poly = None

    R_poly = None
    
    f0_poly = Poly(1, x)
    g0_poly = Poly(1 - 2 * x, x)

    Dmin = None
    Dmax = None

    def __init__(self, N, p, q, Dmin, Dmax):
        self.N = N
        self.p = p
        self.q = q
        self.Dmin = Dmin
        self.Dmax = Dmax
        self.R_poly = Poly(x ** N - 1, x).set_domain(ZZ)

    def generate_f(self):
        num_nonzero = self.N//3

        f1_poly = random_poly(self.N, num_nonzero)

        f_poly = self.f0_poly + self.p * f1_poly

        return f_poly
    
    def generate_g(self):
        num_nonzero =  int(math.sqrt(self.q))

        g1_poly = random_poly(self.N, num_nonzero)

        g_poly = self.f0_poly + self.p * g1_poly

        return g_poly

    def generate_random_keys(self):
        g_poly = self.generate_g()
        tries = 10
        while tries > 0 and (self.h_poly is None):

            f_poly = self.generate_f()

            try:
                self.generate_public_key(f_poly, g_poly)
            except NotInvertible as ex:
                tries -= 1

        if self.h_poly is None:
            raise Exception("Couldn't generate invertible f")

    def generate_public_key(self, f_poly, g_poly):
        self.f_poly = f_poly
        self.g_poly = g_poly

        self.f_p_poly = invert_poly(self.f_poly, self.R_poly, self.p)
        self.f_q_poly = invert_poly(self.f_poly, self.R_poly, self.q)

        p_f_q_poly = (self.p * self.f_q_poly).trunc(self.q)
        h_before_mod = (p_f_q_poly * self.g_poly).trunc(self.q)
        self.h_poly = (h_before_mod % self.R_poly).trunc(self.q)

    def encrypt(self, msg_poly, rand_poly):
        return (((rand_poly * self.h_poly).trunc(self.q) + msg_poly) % self.R_poly).trunc(self.q)

    def decrypt(self, msg_poly):
        a_poly = ((self.f_poly * msg_poly) % self.R_poly).trunc(self.q)
        b_poly = a_poly.trunc(self.p)
        return ((self.f_p_poly * b_poly) % self.R_poly).trunc(self.p)
    
    def hash_message(self, message):
        # Convert the input message (numpy array) to bytes
        if isinstance(message, np.ndarray):
            message = message.tobytes()  # Convert numpy array to bytes
        
        # Initialize the SHA256 hashing object
        hash_obj = SHA256.new()
        hash_obj.update(message)  # Hash the byte-converted message

        # Get the digest and convert it into a polynomial
        hash_digest = hash_obj.digest()
        
        # Unpack the hash digest into bits and reverse the list for little-endian
        msg_poly = Poly(list(np.unpackbits(np.frombuffer(hash_digest, dtype=np.uint8)))[::-1], x).set_domain(ZZ)
        return msg_poly
    
    def generate_w2(self):
        coeffs = [0] * self.N
        ones_position = np.random.choice(range(self.N), 32, replace=False)
        for pos in ones_position:
            coeffs[pos] = choice([1, -1])

        return Poly(coeffs, x)
    
    #precisa passar g_poly
    def generate_w1(self, m_poly, w2):

        sl = (self.f_poly * (m_poly + self.p * w2)).trunc(self.q)
        tl = (self.g_poly * (m_poly + self.p * w2)).trunc(self.q)



        coeffs = [0] * self.N
        non_zero_count = 0
        
        for i in range(self.N):
            m_i = m_poly.coeffs()[i]  if i < len(m_poly.coeffs()) else 0
            sl_i = sl.coeffs()[i]  if i < len(sl.coeffs()) else 0
            tl_i = tl.coeffs()[i]  if i < len(tl.coeffs()) else 0

            if sl_i % self.p != m_i % self.p and tl_i % self.p != m_i % self.p and sl_i % self.p == tl_i % self.p:
                coeffs[i] = (m_i - sl_i) % self.p
            elif sl_i % self.p != m_i % self.p and tl_i % self.p != m_i % self.p and sl_i % self.p != tl_i % self.p:
                coeffs[i] = choice([1, -1])
            elif sl_i % self.p != m_i % self.p and tl_i % self.p == m_i % self.p:
                if np.random.rand() < 0.25:
                    coeffs[i] = (m_i - sl_i) % self.p
            elif sl_i % self.p == m_i % self.p and tl_i % self.p != m_i % self.p:
                if np.random.rand() < 0.25:
                    coeffs[i] = (m_i - tl_i) % self.p

            if coeffs[i] != 0:
                non_zero_count += 1
            
            if non_zero_count > 25:
                break

        for i in range(self.N):
            if np.random.rand() < 1/3:
                m_i = m_poly.coeffs()[i] if i < len(m_poly.coeffs()) else 0
                w1_i = coeffs[i] if i < len(coeffs) else 0
                w2 = w2 - Poly([m_i + w1_i], x)

        return Poly(coeffs, x) 

    def generate_w(self, m_poly):
        w2 = self.generate_w2()
        w1 = self.generate_w1(m_poly, w2)

        return m_poly + w1 + self.p * w2
    
    def sign(self, msg_poly):
        m_poly = self.hash_message(msg_poly)
        w = self.generate_w(m_poly)
        s = (self.f_poly * w % self.R_poly).trunc(self.q)

        return m_poly, s

    def deviation(self, poly1, poly2):
        coeffs = [(float(c1) - float(c2)) for c1, c2 in zip(poly1.all_coeffs(), poly2.all_coeffs())]
        print("Coefficients difference:", np.std(coeffs))
        return np.std(coeffs)

    def verify(self, m_poly, s):
        f0_m = (self.f0_poly * m_poly % self.R_poly).trunc(self.q)
        dev_s_f0_m = self.deviation(s, f0_m)

        if not (self.Dmin <= dev_s_f0_m <= self.Dmax):
            return False

        t = (self.h_poly * s % self.R_poly).trunc(self.q)
        g0_m = (self.g0_poly * m_poly % self.R_poly).trunc(self.q)
        dev_t_g0_m = self.deviation(t, g0_m)

        if not (self.Dmin <= dev_t_g0_m <= self.Dmax):
            return False

        return True  # Signature is valid
