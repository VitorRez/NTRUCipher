from NTRU import *
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
    print(f"[NEW CONNECTION] {addr} connected.")
    bytes_pub_key = pickle.dumps(pub_key)
    conn.send(bytes_pub_key)
    bytes_enc_text = get_msg(conn, addr)
    if bytes_enc_text != DISCONNECT_MESSAGE:
        enc_text = pickle.loads(bytes_enc_text)
        text = decrypt(priv_key, enc_text)
        print(text.decode('utf-8'))
    
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
    priv_key, pub_key = generate(N=251, p=3, q=128)
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