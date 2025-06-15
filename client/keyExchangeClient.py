from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pad1


class RSAExchange:
    def __init__(self, sock):
        self.sock = sock


    def get_public_key(self):
        header = self.sock.recv(4)
        if not header:
            return None
        
        if header != b"KEYE":
            return None
        
        public_key_data = b""
        while True:
            chunk = self.sock.recv(1024)
            if not chunk:
                break  # Connection closed
            public_key_data += chunk
            if len(chunk) < 4096:
                break  # End of data (assuming sender sent everything at once)

        self.__public_key = serialization.load_pem_public_key(public_key_data)


    def switch_keys(self, key):
        self.get_public_key()
        encrypted_message = self.__public_key.encrypt(key, pad1.OAEP(mgf=pad1.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.sock.sendall(encrypted_message)
