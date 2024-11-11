PyNTRU is a package containing an implementation of NTRU, a public-key post-quantum cryptosystem. It consists of two main
algorithms: NTRUEncrypt, for data encryption, and NTRU Signature Scheme (NSS) for digital signatures.

The main module of this code is located in `NTRU.py`. This file contains all the main functions that PyNTRU can perform. These
functions are as follow:

`generate(N=256, p=3, q=128, Dmin=55, Dmax=87)`: 

- Generates an NTRU key pair.
- `N`, `p`, `q` are the main attributes used to generate the keys.
- The recommended size of `N` is 251 due to computational time costs (using 251 takes almost half the time of 256). However, using 256 makes it easier to hash keys and ciphers using SHA256, and since the key will be ideally generated only one time per user, the increase in time won't have a big effect on the algorithm's efficiency, so we decided to use 256.
- `Dmin` and `Dmax` are parameters used on NSS while verifying a signature.

`encrypt(pub_key, input_str)`:

- Encrypts a message encoded in `input_str`.
- We recommend the use of a key encapsulation mechanism, due to the limited size of `input_str` (32 characters). However, we are currently working on a way to encrypt larger messages by parsing them into smaller messages.

`decrypt(priv_key, input)`:

- Decrypts the content of `input`.

`sign(priv_key, pub_key, input_str)`:

- Signs the message encoded in `input_str`.
- Contrary to other cryptosystems, this function also takes the public key as a parameter. Due to limitations of the NTRU Signature Scheme (NSS), a signature must be verified when it's created.

`verify(pub_key, signed_input)`:

- Verifies the validity of the signed message.

Listed below you can see an example of code using the functions of PyNTRU:

### Encryption Example:

```python
from PyNTRU.NTRU import *

# Message that will be encrypted
msg = b'texttexttexttexttexttexttexttext'

# Generation of keys
priv_key, pub_key = generate()

# Encryption
enc_text = encrypt(pub_key, msg)

# Decryption
plain_text = decrypt(priv_key, enc_text)

if plain_text == msg:
    print('success!') 
```

### Signature Example:

```python
from PyNTRU.NTRU import *

#message that will be signed
msg = b'Lorem ipsum odor amet, consectetuer adipiscing elit. Neque bibendum nulla lacinia pulvinar elementum non dui! Rhoncus justo nullam placerat eu duis ridiculus luctus. Ut egestas ante justo fermentum suspendisse consequat ligula. Curabitur blandit magnis dig'

#generation of keys
keys = generate()

#signing the message
signed_msg = sign(keys['private_key'], keys['public_key'], msg)

#signature verification
if verify(keys['public_key'], signed_msg):
    print('Valid signature!')
else:
    print('Invalid signature.')
```

