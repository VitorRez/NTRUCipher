from NTRU import *

# Generate the keys
priv_key, pub_key = generate(N=251, p=3, q=128)

# Example input array for encryption
input_arr = b"banana"

# Encrypt the input array using the public key
encrypted = encrypt(pub_key, input_arr)
print("Encrypted:", encrypted)

# Decrypt the encrypted array using the private key
decrypted = decrypt(priv_key, encrypted)
print("Decrypted:",decrypted)

# Sign the input array using private key
s1, s2 = sign(priv_key, input_arr)

# Verify the input array using public key
verify(pub_key, input_arr, s1, s2)
