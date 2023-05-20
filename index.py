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

# Encryption constants
KEY_SIZE = 16  # AES-128
SALT_SIZE = 16
IV_SIZE = 16
ITERATIONS = 100000

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

def generate_mac(key, message):
    hmac_msg = message.encode()  # Convert message to bytes if it's a string

    mac = hmac.new(key, hmac_msg, hashlib.sha256)
    return mac.hexdigest()

def register():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")

    salt = os.urandom(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(password.encode(), AES.block_size))

    if checkIfTheEmailAlreadyExist(email):
        print("Error: Duplicated e-mail. Please, try another e-mail")
        return

    user_id = uuid.uuid4()

    with open(CREDENTIALS_FILE, "a") as file:
        file.write(f"{email}:{b64encode(salt).decode()}:{b64encode(cipher.iv).decode()}:{b64encode(ciphertext).decode()}:{user_id}\n")

    print("Registration successful!")

def login():

    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")

    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            stored_email, stored_salt, stored_iv, stored_ciphertext, user_id = line.strip().split(":")
            if email == stored_email:
                salt = b64decode(stored_salt)
                iv = b64decode(stored_iv)
                ciphertext = b64decode(stored_ciphertext)
                break
        else:
            print("Invalid email or password!")
            return False, 0, 0, 0, 0
        
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_CBC, iv )
    try:
        unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        print("Login successful!")
        return True, key, iv, salt, user_id
    except:
        print("Invalid email or password!")
        return False, 0, 0, 0, 0

def loggedFlow(key, iv, salt, user_id):
    while True: 
        print("1. Insert a new register")
        print("2. List registers")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            insertNewRegister(key, iv, salt, user_id)

        elif choice == "2":
            listRegisters(key, iv, salt, user_id)

        elif choice == "3":
            exit(0)
        else:
            print("Invalid choice. Please try again.")

def listRegisters(key, iv, salt, user_id):

    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        with open(REGISTER_PATH+user_id+".txt", "r") as file:
            print("\n--- LIST OF DESCRIPTIONS ---\n")
            for line in file:
                stored_timestamp, stored_ciphertext, stored_user_id, stored_hmac = line.strip().split(":")
                original_description = unpad(cipher.decrypt(b64decode(stored_ciphertext)), AES.block_size).decode()
                now = datetime.fromtimestamp(float(stored_timestamp))
                
                print(original_description)
                print(f"Date: {now}")
                print("Validity: " + "Válido" if hmac.compare_digest(stored_hmac, generate_mac(key, original_description)) else "Não válido")
                print("\n")   
    except FileNotFoundError:
        print("No registers found") 
    except ValueError:
        print("Error during the decryption")
    return

def insertNewRegister(key, iv, salt, user_id):
    description = input("Enter your description: ")
    now = datetime.now()
    now_timestamp = datetime.timestamp(now)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(description.encode(), AES.block_size))

    new_hmac = generate_mac(key, description)

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
            success, key, iv, salt, user_id = login()

            if(not success):
                continue

            loggedFlow(key, iv, salt, user_id)

        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
