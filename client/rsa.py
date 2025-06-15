from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pad1
from cryptography.hazmat.primitives import hashes
import os
import tempfile


class RSA:
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public_key = private_key.public_key()
        return (private_key, public_key)


    def public_key_to_bytes(self, public_key):
        public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return public_key_bytes
    

    def private_key_to_bytes(self, private_key):
        key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
        return key_bytes
    

    def load_public_key(self, pem_str):
        pem_bytes = pem_str.encode()  # convert string to bytes
        public_key = serialization.load_pem_public_key(pem_bytes)
        return public_key
    

    def load_private_key(self, pem_str):
        pem_bytes = pem_str.encode()  # convert string to bytes
        private_key = serialization.load_pem_private_key(pem_bytes,password=None,)
        return private_key


    def encrypt(self, public_key ,msg):
        encrypted = public_key.encrypt(msg,pad1.OAEP(mgf=pad1.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        return encrypted
    

    def decrypt(self, private_key, msg):
        decrypted =  private_key.decrypt(msg,pad1.OAEP(mgf=pad1.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        return decrypted


    def encrypt_file(self, file_path, public_key):
        max_chunk_size = 190  # max bytes for 2048-bit RSA + OAEP-SHA256

        # Create a temp file to write encrypted data
        with open(file_path, "rb") as f_in, tempfile.NamedTemporaryFile("wb", delete=False) as tmp_file:
            while True:
                chunk = f_in.read(max_chunk_size)
                if not chunk:
                    break
                encrypted_chunk = public_key.encrypt(chunk,pad1.OAEP(mgf=pad1.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None,))
                tmp_file.write(len(encrypted_chunk).to_bytes(2, "big"))
                tmp_file.write(encrypted_chunk)

        # Replace original file with encrypted temp file
        os.replace(tmp_file.name, file_path)
        print(f"File encrypted in-place: {file_path}")
    

    def decrypt_file(self, file_path, private_key):
        # Create a temp file to write decrypted data
        with open(file_path, "rb") as f_in, tempfile.NamedTemporaryFile("wb", delete=False) as tmp_file:
            while True:
                length_bytes = f_in.read(2)
                if not length_bytes:
                    break
                chunk_len = int.from_bytes(length_bytes, "big")
                encrypted_chunk = f_in.read(chunk_len)
                decrypted_chunk = private_key.decrypt(encrypted_chunk,pad1.OAEP(mgf=pad1.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None,))
                tmp_file.write(decrypted_chunk)

        # Replace original file with decrypted temp file
        os.replace(tmp_file.name, file_path)
        print(f"File decrypted in-place: {file_path}")
    

if __name__ == "__main__":
    x = RSA()
    args = x.generate_key_pair()
    print(args[0])
    print(args[1])
