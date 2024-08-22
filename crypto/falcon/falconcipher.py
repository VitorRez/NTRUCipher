import numpy as np
from sympy import Poly
from sympy.abc import x
from scipy.stats import norm

def discrete_gaussian_sample(sigma, size):
        return np.round(norm.rvs(scale=sigma, size=size)).astype(int)

def gaussian_sample_poly(sigma, N, q):
    """Generate a polynomial with coefficients sampled from a Gaussian distribution."""
    coefficients = discrete_gaussian_sample(sigma, N)
    return Poly(coefficients, x).trunc(q)



