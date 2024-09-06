from crypto.ciphers import *
from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import *

priv_key_ntru, pub_key_ntru = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)

#aes_key = get_random_bytes(16)

msg = b'banana'
msg2 = b'laranja'

m_poly1, s1 = sign(priv_key_ntru, msg)
m_poly2, s2 = sign(priv_key_ntru, msg2)
print(verify(pub_key_ntru, m_poly1, s1))
print(verify(pub_key_ntru, m_poly1, s2))
print(verify(pub_key_ntru, m_poly2, s1))
print(verify(pub_key_ntru, m_poly2, s2))

#output = encrypt(pub_key_ntru, msg)

#print(output)

#clear_msg = decrypt(priv_key_ntru, output)

#clear_msg = [(x + 256) % 256 for x in clear_msg]

#print(clear_msg)

# Convert the list of integers to a byte array
#byte_data = bytes(clear_msg)

#try:
#    # Try to decode the byte data back to a string (if it contains textual data)
#    decoded_msg = byte_data.decode('utf-8')
#    print("Decrypted:", decoded_msg)
#except UnicodeDecodeError:
#    # If it's not a valid UTF-8 string, print the byte data instead
#    print("Decrypted message cannot be decoded as UTF-8 string.")
#    print("Byte data:", byte_data)

#e = CipherHandler(aes_key, pub_key_ntru)
#enc_text = e.e_protocol(msg)
#print(enc_text)

#plaintext = e.d_protocol(enc_text, priv_key_ntru)
#print(plaintext)