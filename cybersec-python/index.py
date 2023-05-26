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
KEY_SIZE = 32       # AES-128
SALT_SIZE = 16
ITERATIONS = 250000 #Rounds to create the secure representation of the user password
CIPHER_MODES = {
    'CBC': AES.MODE_CBC,
    'CTR': AES.MODE_CTR
}



# File to store user credentials
CREDENTIALS_FILE = "credentials.txt"
REGISTER_PATH = "data/"



def checkIfTheEmailAlreadyExist(email):
    try:
        with open(CREDENTIALS_FILE, "r") as file:
            for line in file:
                stored_email = line.strip().split(":")[0]
                if stored_email == email:
                    return True
            return False
    except FileNotFoundError:
        open(CREDENTIALS_FILE, "x")
        return False



def generate_mac(key, message, algorithm):
    hmac_msg = message.encode()  # Convert message to bytes if it's a string
    if algorithm == 'SHA256':
        mac = hmac.new(key, hmac_msg, hashlib.sha256)
    elif algorithm == 'SHA512':
        mac = hmac.new(key, hmac_msg, hashlib.sha512)
    else:
        raise ValueError('Unsupported HMAC algorithm.')
    return mac.hexdigest()



def add_block_to_blockchain_cipher(block_i_want_to_add, last_b, hash_type, user_iv, user_key, cipher_mode):
    if hash_type == 'SHA256':
        block_hash = hashlib.sha256(last_b.encode('utf-8')).hexdigest()
    elif hash_type == 'SHA512':
        block_hash = hashlib.sha512(last_b.encode('utf-8')).hexdigest()
    else:
        raise ValueError('Something went wrong with the hash type!')

    my_block = block_hash + ":" + block_i_want_to_add

    if cipher_mode == 'CBC':
        aes_block = AES.new(user_key, AES.MODE_CBC, user_iv).encrypt(pad(my_block.encode(), AES.block_size))

    elif cipher_mode == 'CTR':
        aes_block = AES.new(user_key, AES.MODE_CTR, nonce = user_iv).encrypt(my_block.encode())

    return aes_block



def register():
    flag = True
    while(flag):
        email = input("Enter your email: ")
    
        if checkIfTheEmailAlreadyExist(email):
            print("Error: Duplicated email. Please try another email.\n")
        else:
            password = getpass.getpass("Enter your password: ")
            cipher_mode = input("Enter the cipher mode:\n CBC\n CTR\n").upper()
            # Verifica que el modo de cifrado ingresado sea válido
            while(cipher_mode not in CIPHER_MODES):
                print("Invalid cipher mode!")
                cipher_mode = input("Enter the cipher mode:\n CBC\n CTR\n").upper()
            hash_type = input("Enter the hash type you want to use (SHA256 or SHA512), will be used in HMAC algorithm: ").upper()
            while(hash_type not in ['SHA256', 'SHA512']):
                print("Invalid cipher mode!")
                hash_type = input("Enter the hash type you want to use (SHA256 or SHA512), will be used in HMAC algorithm: ").upper()
            flag = False

    salt = os.urandom(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS) #Hash with multiple rounds, equivalent to, for example, concatante the password and the salt, do their hash, with multiple rounds

    #iv size must be:
    # to CBC -> 16bytes
    # to CTR -> 12bytes

    if cipher_mode == 'CBC':
        iv = os.urandom(16)
    elif (cipher_mode == 'CTR'):
        iv = os.urandom(12)
        
    user_id = uuid.uuid4()

    with open(CREDENTIALS_FILE, "a") as file:
        file.write(
            f"{email}:{b64encode(salt).decode()}:{b64encode(iv).decode()}:{b64encode(key).decode()}:{str(user_id)}:{cipher_mode}:{hash_type}\n")

    print("Registration successful!")



def login():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")


    with open(CREDENTIALS_FILE, "r") as file:
        for line in file:
            stored_email, stored_salt, stored_iv, stored_key, user_id, cipher_mode, hash_type = line.strip().split(":")
            if email == stored_email:
                salt = b64decode(stored_salt)
                iv = b64decode(stored_iv)
                stored_key_b64 = b64decode(stored_key)
                break
        else:
            print("Invalid email or password!")
            return None

    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

    if key == stored_key_b64:
        print("Login successful!")
        return True, key, iv, salt, user_id, cipher_mode, hash_type
    else:
        print("Invalid email or password!")
        return None



def loggedFlow(key, iv, salt, user_id, cipher_mode, hash_type):  
    while True: 
        print("1. Insert a new register")
        print("2. List registers")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            insertNewRegister(key, iv, salt, user_id, cipher_mode, hash_type)  
        elif choice == "2":
            listRegisters(key, iv, salt, user_id, cipher_mode, hash_type)  
        elif choice == "3":
            exit(0)
        else:
            print("Invalid choice. Please try again.")



def listRegisters(key, iv, salt, user_id, cipher_mode, hash_type):
    try:
        with open(REGISTER_PATH+user_id+".txt", "r") as file:
            print("\n--- LIST OF DESCRIPTIONS ---\n")
            for line in file:
                if cipher_mode == 'CBC':
                    original_description = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(b64decode(line)), AES.block_size).decode()
                elif cipher_mode == 'CTR':
                    original_description = AES.new(key, AES.MODE_CTR, nonce=iv).decrypt(b64decode(line)).decode()

                stored_hash_previous_block, stored_timestamp, stored_text, stored_hmac = original_description.strip().split(":")
                now = datetime.fromtimestamp(float(stored_timestamp))

                print(stored_text)
                print(f"Date: {now}")
                print("Validity: " + "Valid" if hmac.compare_digest(stored_hmac, generate_mac(key, stored_text, hash_type)) else "Not valid")
                print("\n")   
    except FileNotFoundError:
        print("No registers found") 
    except ValueError:
        print("Error during the decryption")
    return



def insertNewRegister(key, iv, salt, user_id, cipher_mode, hash_type):
    description = input("Enter your description: ")
    now = datetime.now()
    now_timestamp = datetime.timestamp(now)
    new_hmac = generate_mac(key, description, hash_type)

    aux = f"{now_timestamp}:{description}:{new_hmac}\n"

    #If a certain file does not exist, one is created
    if (not os.path.isfile(REGISTER_PATH+user_id+".txt")):
        with open(REGISTER_PATH+user_id+".txt", "a") as file:
            file.write("")

    last_block = ""
    with open(REGISTER_PATH+user_id+".txt", "r", encoding="utf-8") as file:
        try:
            paragraphs = file.read().split('\n')
            last_block = paragraphs[-2].rstrip()
            if cipher_mode == 'CBC':
                last_block = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(b64decode(last_block)), AES.block_size).decode()
            elif cipher_mode == 'CTR':
                last_block = AES.new(key, AES.MODE_CTR, nonce=iv).decrypt(b64decode(last_block)).decode()
        except IndexError:
            last_block = ""

    aux = add_block_to_blockchain_cipher(aux, last_block, hash_type, iv, key, cipher_mode)

    aux = b64encode(aux).decode('utf-8') + "\n"

    with open(REGISTER_PATH+user_id+".txt", "a") as file:
        file.write(aux)

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
            if login_result is not None:
                # Si login fue exitoso
                success, key, iv, salt, user_id, cipher_mode, hash_type = login_result
                loggedFlow(key, iv, salt, user_id, cipher_mode, hash_type)  # <-- Aquí está la corrección
        elif choice == "3":
            exit(0)
        else:
            print("Invalid choice!")



if __name__ == "__main__":
    main()
