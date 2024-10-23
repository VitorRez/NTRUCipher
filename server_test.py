from crypto.ciphers import *
from crypto.ntru.NTRU import *
from crypto.ntru.ntrucipher import *
from crypto.ntru.ntrusign import *
import pickle
import socket
import threading

HEADER = 2048
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

def handle_client(conn, addr, priv_key, pub_key):
    print(f"[NEW CONNECTIsON] {addr} connected.")

    #handshake

    #receive public key
    pub_key_c = pickle.loads(get_msg(conn, addr))

    #send public key
    conn.send(pickle.dumps(pub_key))

    #receive enc_text
    enc_text = pickle.loads(get_msg(conn, addr))
    d_enc = CipherHandler(0, priv_key)
    clear_text = d_enc.d_protocol(enc_text, priv_key)
    print(clear_text)

    #send ACK
    conn.send("Ok!")

    #receive signature
    m = pickle.loads(get_msg(conn, addr))
    signature = pickle.loads(get_msg(conn, addr))

    #send ACK
    if verify(pub_key_c, m, signature):
        conn.send("Ok!")
    else:
        conn.send("Invalid signature")

    conn.close()

def get_msg(conn, addr):
    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length)
            return msg

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    priv_key, pub_key = generate(N=251, p=3, q=128, Dmin=55, Dmax=87)
    print(f"[LISTENING] Server is listerning on {SERVER}")
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr, priv_key, pub_key))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    finally:
        print("[SERVER CLOSED]")

start_server()