PyNTRU is a package containing an implementation of NTRU, a public-key post-quantum cryptosystem. It consists of two main
algorithms: NTRUEncrypt, for data encryption, and NTRU Signature Scheme (NSS) for digital signatures.

The main module of this code is located in NTRU.py. This file contains all the main functions that PyNTRU can perform. These
functions are as follow:

generate(N=256, p=3, q=128, Dmin=55, Dmax=87): 

- generates an NTRU key pair.
- N, p, q are the main attributes used to generate the keys.
- The recommended size of N is 251 due to computational time costs ( using 251 take almost half the time of 256 ). However, using 256 makes it easier to hash keys and ciphers using SHA256, and since the key will be ideally generated only one time per user the increase in time won't have big effects on the algorithm efficience, so we decided to use 256.
- Dmin and Dmax are parameters used on NSS while verifying a signature.

encrypt(pub_key, input_str):

- encrypts a message encode in input_str

decrypt(priv_key, input):

- decrypts the content of input

sign(priv_key, pub_key, input_str):

- signs the message encoded in input_str
- contrary to other cryptosystems this function also takes the public key as a parameter. Due to limitations of the NTRU Signature Scheme (NSS), a signature must be verified when it's created.

verify(pub_key, signed_input):

- verifys the validity of the signed message