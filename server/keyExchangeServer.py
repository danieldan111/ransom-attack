from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pad1
import pickle
import sys
import os


ROOT = sys.path[0]
PATH = ROOT + "/rsa_key.pkl"
if not os.path.isfile(PATH):
    PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pem = PRIVATE_KEY.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,  encryption_algorithm=serialization.NoEncryption())
    with open(PATH, "wb") as f:
        pickle.dump(pem, f)
else:
    with open(PATH, "rb") as f:
        pem = pickle.load(f)
        PRIVATE_KEY = serialization.load_pem_private_key(pem,password=None,)


PUBLIC_KEY = PRIVATE_KEY.public_key()
class RSAExchange:
    def __init__(self, sock):
        self.sock = sock
        self.__private_key = PRIVATE_KEY
        self.__public_key = PUBLIC_KEY
        self.__public_key_bytes = self.__public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)


    def encrypt(self, msg):
        encrypted = self.__public_key.encrypt(msg,pad1.OAEP(mgf=pad1.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        return encrypted
    

    def decrypt(self, msg):
        decrypted =  self.__private_key.decrypt(msg,pad1.OAEP(mgf=pad1.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        return decrypted
    

    def send_public_key(self):
        self.sock.sendall(b"KEYE" + self.__public_key_bytes)
        print("Public key sent")


    def switch_keys(self):
        self.send_public_key()
        try:
            encrypted_message = self.sock.recv(256)
        except Exception as e:
            return None
        else:
            if not encrypted_message:
                return None
            
        return (self.decrypt(encrypted_message))
