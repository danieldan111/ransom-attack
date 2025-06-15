# 🛡️ Ransomware Simulation Project (Educational Use Only)

## 📜 Description

This project simulates a basic ransomware attack workflow for **educational and cybersecurity research purposes only**.

The system is composed of a **Client** and a **Server**:

- The **Client** receives an RSA **public key** from the server and uses it to **encrypt all files under a specified path**.
- The **RSA private key**, along with the **victim's MAC address**, is stored in a **SQLite database** (`RansomKeys.db`) on the server.
- Each record in the database includes:
  - `mac`: victim's MAC address (as the primary key)
  - `rsa_key`: pickled and encoded private key
  - `locked`: boolean flag (`True` means still encrypted)

## 🔐 How it Works

### 1. **Encryption Phase (Client)**
- The client receives an RSA public key.
- It recursively walks through all files under a specified path (changeable in code).
- Each file is encrypted **chunk-by-chunk** using the public RSA key.
- The private RSA key is never stored on the client side.

### 2. **Key Storage (Server)**
- Upon encryption, the private key and MAC address are saved in a server-side SQLite database (`RansomKeys.db`).
- The record includes a `locked=True` flag.

### 3. **Decryption Phase (Client)**
- The client periodically asks the server for the private key.
- The server checks the `locked` flag:
  - If `locked=True`: key is not sent.
  - If `locked=False`: the private key is returned, and the client decrypts all files.

### 4. **Unlocking (Server)**
- The server owner must run `db.py` and manually set the `locked` flag to `False` for a given MAC address using the `unlock(mac)` function.

## ⚠️ Warning

> 🚨 This project is for **educational** and **ethical** cybersecurity testing only. Do **not** use it for unauthorized access or harm. Misuse may be illegal and unethical.

## 🔧 Configuration

- Modify the path to encrypt/decrypt in the client source code.
- The database file is stored by default as `RansomKeys.db` in the script directory.

## 🧪 Example Usage

```python
# On server:
from db import db
database = db()
database.unlock("00:1A:2B:3C:4D:5E")  # Unlock victim by MAC address
