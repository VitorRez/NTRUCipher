from crypto.ciphers import *
from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import *
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

def enc_text(text):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    bytes_pub_key = client.recv(2048)
    pub_key = pickle.loads(bytes_pub_key)
    enc_text = encrypt(pub_key, text)
    bytes_enc_text = pickle.dumps(enc_text)
    send(bytes_enc_text, client)
    client.close()

enc_text(b"banana")