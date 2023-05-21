import os
import getpass
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Protocol.KDF import PBKDF2
from datetime import datetime
import uuid
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend




# Encryption constants
# Encryption constants
KEY_SIZE = 16  # AES-128
SALT_SIZE = 16
IV_SIZE = 12  # Updated to 12 bytes for CTR mode
ITERATIONS = 100000
CIPHER_MODES = {
    'CBC': AES.MODE_CBC,
    'CTR': AES.MODE_CTR
}



# File to store user credentials
CREDENTIALS_FILE = "credentials.txt"
REGISTER_PATH = "data/"

def checkIfTheEmailAlreadyExist(email):
    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            stored_email = line.strip().split(":")[0]
            if stored_email == email:
                return True
    return False

def generate_mac(key, message, algorithm):
    hmac_msg = message.encode()  # Convert message to bytes if it's a string

    mac = hmac.new(key, hmac_msg, algorithm)
    return mac.hexdigest()



def register():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")
    cipher_mode = input("Enter the cipher mode (CBC or CTR): ").upper()

    # Verifica que el modo de cifrado ingresado sea válido
    if cipher_mode not in CIPHER_MODES:
        print("Invalid cipher mode!")
        return

    salt = os.urandom(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

    if cipher_mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(password.encode(), AES.block_size))
        iv = cipher.iv
    else:  # cipher_mode == 'CTR'
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(password.encode())
        iv = cipher.nonce

    if checkIfTheEmailAlreadyExist(email):
        print("Error: Duplicated email. Please try another email.")
        return

    user_id = uuid.uuid4()

    with open(CREDENTIALS_FILE, "a") as file:
        file.write(
            f"{email}:{b64encode(salt).decode()}:{b64encode(iv).decode()}:{b64encode(ciphertext).decode()}:{str(user_id)}:{cipher_mode}\n"
        )

    print("Registration successful!")



def login():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")

    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            stored_email, stored_salt, stored_iv, stored_ciphertext, user_id, cipher_mode = line.strip().split(":")
            if email == stored_email:
                salt = b64decode(stored_salt)
                iv = b64decode(stored_iv)
                ciphertext = b64decode(stored_ciphertext)
                break
        else:
            print("Invalid email or password!")
            return None

    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

    if cipher_mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    else:  # cipher_mode == 'CTR'
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        plaintext = cipher.decrypt(ciphertext).decode()

    if plaintext == password:
        print("Login successful!")
        return True, key, iv, salt, user_id, cipher_mode
    else:
        print("Invalid email or password!")
        return None




def loggedFlow(key, iv, salt, user_id, cipher_mode):  # Añade cipher_mode como argumento
    while True: 
        print("1. Insert a new register")
        print("2. List registers")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            insertNewRegister(key, iv, salt, user_id, cipher_mode)  # Pasa cipher_mode

        elif choice == "2":
            listRegisters(key, iv, salt, user_id, cipher_mode)  # Pasa cipher_mode aquí también

        elif choice == "3":
            exit(0)
        else:
            print("Invalid choice. Please try again.")


def listRegisters(key, iv, salt, user_id, cipher_mode):
    try:
        with open(REGISTER_PATH+user_id+".txt", "r") as file:
            print("\n--- LIST OF DESCRIPTIONS ---\n")
            for line in file:
                stored_timestamp, stored_ciphertext, stored_user_id, stored_hmac = line.strip().split(":")
                if cipher_mode == 'CBC':
                    cipher = AES.new(key, AES.MODE_CBC, iv) 
                    original_description = unpad(cipher.decrypt(b64decode(stored_ciphertext)), AES.block_size).decode()
                else:  # cipher_mode == 'CTR'
                    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
                    original_description = cipher.decrypt(b64decode(stored_ciphertext)).decode()
                now = datetime.fromtimestamp(float(stored_timestamp))

                print(original_description)
                print(f"Date: {now}")
                print("Validity: " + "Válido" if hmac.compare_digest(stored_hmac, generate_mac(key, original_description, hashlib.sha256)) else "Não válido")
                print("\n")   
    except FileNotFoundError:
        print("No registers found") 
    except ValueError:
        print("Error during the decryption")
    return







def insertNewRegister(key, iv, salt, user_id, cipher_mode):
    description = input("Enter your description: ")
    now = datetime.now()
    now_timestamp = datetime.timestamp(now)

    if cipher_mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(description.encode(), AES.block_size))
    else:# cipher_mode == 'CTR'
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        ciphertext = cipher.encrypt(description.encode())

    new_hmac = generate_mac(key, description, hashlib.sha256) 

    with open(REGISTER_PATH+user_id+".txt", "a") as file:
        file.write(f"{now_timestamp}:{b64encode(ciphertext).decode()}:{user_id}:{new_hmac}\n")

    print("Insertion successful!")

    

def main():
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            register()
        elif choice == "2":
            login_result = login()  # <-- Aquí está la corrección
            if login_result is not None:  # Si login fue exitoso
                success, key, iv, salt, user_id, cipher_mode = login_result
                loggedFlow(key, iv, salt, user_id, cipher_mode)  # <-- Aquí está la corrección
        elif choice == "3":
            exit(0)
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
