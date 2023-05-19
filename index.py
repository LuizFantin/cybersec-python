import os
import getpass
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Protocol.KDF import PBKDF2

# Encryption constants
KEY_SIZE = 16  # AES-128
SALT_SIZE = 16
IV_SIZE = 16
ITERATIONS = 100000

# File to store user credentials
CREDENTIALS_FILE = "credentials.txt"

def checkEmailAlreadyExist(email):
    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            stored_email = line.strip().split(":")[0]
            if stored_email == email:
                return 1
    return 0

def register():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")

    salt = os.urandom(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(password.encode(), AES.block_size))

    if checkEmailAlreadyExist(email) == 1:
        print("Error: Duplicated e-mail. Please, try another e-mail")
        return

    with open(CREDENTIALS_FILE, "a") as file:
        file.write(f"{email}:{b64encode(salt).decode()}:{b64encode(cipher.iv).decode()}:{b64encode(ciphertext).decode()}\n")

    print("Registration successful!")

def login():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")

    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            stored_email, stored_salt, stored_iv, stored_ciphertext = line.strip().split(":")
            if email == stored_email:
                salt = b64decode(stored_salt)
                iv = b64decode(stored_iv)
                ciphertext = b64decode(stored_ciphertext)
                break
        else:
            print("Invalid email or password!")
            return

    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        print("Login successful!")
    except:
        print("Invalid email or password!")

def main():
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
