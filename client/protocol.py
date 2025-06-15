from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


DEBUG = True
class Secured_socket:
    def __init__(self, sock, header, aes_key, aes_iv):
        self.format = "utf-8"
        self.__sock = sock
        self.__header = header
        self.__aes_key = aes_key
        self.__iv = aes_iv


    def close(self):
        self.__sock.close()


    def send(self, msg):
        if DEBUG:
            print(f"[->]{msg}")
            
        # Encrypt the message using AES-CBC
        cipher = AES.new(self.__aes_key, AES.MODE_CBC, self.__iv)
        padded_msg = pad(msg.encode(self.format), AES.block_size)
        encrypted_msg = cipher.encrypt(padded_msg)

        # Create and send the header (length of the encrypted message)
        header = str(len(encrypted_msg)).zfill(self.__header)
        msg = header.encode(self.format) + encrypted_msg
        self.__sock.send(msg)


    def recv(self):
        # Read the fixed-length header
        header_bytes = self.__sock.recv(self.__header)
        if not header_bytes: return None
        header = int(header_bytes.decode(self.format))

        # Read the encrypted message based on the header
        encrypted_msg = self.__sock.recv(header)

        # Decrypt the message using AES-CBC
        cipher = AES.new(self.__aes_key, AES.MODE_CBC, self.__iv)
        padded_msg = cipher.decrypt(encrypted_msg)
        msg = unpad(padded_msg, AES.block_size).decode(self.format)

        if DEBUG:
            print(f"[<-]{msg}")

        return msg


    def confirm(self):
        self.send("CNFM")
    

    def timeout(self, sec):
        self.__sock.settimeout(sec)
    

    