from crypto.ciphers import *
from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import *
from crypto.ntru.ntrusign import *
from crypto.PBKDF import *
import pickle
import socket

HEADER = 2048
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

def send(msg, client):
    message = msg
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)

def send_to_server(text, c_pub_key, enc_key, aes_key, password_hash, salt):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

    #handshake

    #send public key
    send(pickle.dumps(c_pub_key), client)

    #receive public key
    pub_key_s = pickle.loads(client.recv(2048))

    #send enc_text
    c_enc = CipherHandler(aes_key, pub_key_s)
    enc_text = c_enc.e_protocol(text)
    send(pickle.dumps(enc_text), client)

    #receive ACK
    print(client.recv(2048))

    #send signature
    if verify_password("amobanana", password_hash):
        priv_key = decrypt_pbkdf(enc_key, password_hash, salt)
        signature = sign(priv_key, c_pub_key)
        send(pickle.dumps(signature[0]), client)
        send(pickle.dumps(signature[1]), client)

    #receive ACK
    print(client.recv(2048))

    client.close()

msg = "banana"
password = "amobanana"
password_hash = create_hash(password)
salt = get_random_bytes(16)

c_priv_key, c_pub_key = priv_key_ntru, pub_key_ntru = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)
c_aes_key = get_random_bytes(16)

enc_key = encrypt_pbkdf(priv_key_ntru, password, salt)

send_to_server(msg, c_pub_key, enc_key, c_aes_key, password_hash, salt)


