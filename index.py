import os
import time
import glob
import getpass
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Protocol.KDF import PBKDF2
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5     #   RSA digital signature protocol according to PKCS#1 v1.5
from Crypto.Hash import SHA512, SHA256
from datetime import datetime
import uuid
import hmac
import hashlib


# Encryption constants
# Encryption constants
KEY_SIZE = 16  # AES-128
SALT_SIZE = 16
IV_SIZE = 12  # Updated to 12 bytes for CTR mode
ITERATIONS = 100000
CIPHER_MODES = {
    'CBC': AES.MODE_CBC,
    'CTR': AES.MODE_CTR,
    'RSA': RSA
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


def register():
    flag = True
    time.sleep(0.25)
    while(flag):
        os.system('clear')
        print("=== Register ===\n")
        email = input("Enter your email: ")
    
        if checkIfTheEmailAlreadyExist(email):
            print("Error: Duplicated email. Please try another email.\n")
        else:
            password = getpass.getpass("Enter your password: ")
            cipher_mode = input("Enter the cipher mode (CBC or CTR). Type 0 to cancel: ").upper()
            # Verifica que el modo de cifrado ingresado sea válido
            while(cipher_mode not in CIPHER_MODES):
                print("Invalid cipher mode!")
                cipher_mode = input("Enter the cipher mode (CBC or CTR). Type 0 to cancel.\n").upper()
            hash_type = input("Enter the hash type to use HMAC algorithm (SHA256 or SHA512): ").upper()
            while(hash_type not in ['SHA256', 'SHA512']):
                print("Invalid hash type!")
                hash_type = input("Enter the hash type to use HMAC algorithm (SHA256 or SHA512): ").upper()

            
            # Generate keypair to sign using RSA:
            print("\n=============================================================\n")
            
            
            print("Generating an RSA keypair. The filename will use your email. Store it after registration is complete!")
            try:
                key = RSA.generate(2048)
                #   Generate private key (key pair)
                f = open(email + '_private_key.pem', "wb")
                f.write(key.exportKey('PEM'))
                f.close()
                
                #   Generate public key
                pubkey = key.publickey().exportKey('PEM')
                f = open('pubkeys/' + email + '_public_key.pem', "wb")
                f.write(pubkey)
                f.close()
                
                #   Success prompt
                print('\n=== Process Finished ===\n')
                print("The private and public keys have been generated.")
                print("Don't forget to store private key somewhere safe!")
                input("Press any key to continue...")
                flag = False
                #   For testing:
                #resultBool = pubkey.has_private()  #   Check if the public key has private key attached
                #print('Should be false: ', resultBool)
            except:
                print("Failed generating keys, something went wrong!\n")
                return
            

    salt = os.urandom(SALT_SIZE)
    if cipher_mode == 'CTR':
        iv = os.urandom(12)
    elif cipher_mode == 'CBC':
        iv = os.urandom(16)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS) #Hash with multiple rounds
    user_id = uuid.uuid4()

    with open(CREDENTIALS_FILE, "a") as file:
        file.write(
            f"{email}:{b64encode(salt).decode()}:{b64encode(iv).decode()}:{b64encode(key).decode()}:{str(user_id)}:{cipher_mode}:{hash_type}\n")

    print("\n=== Registration successful! ===\n")


def login():
    time.sleep(0.25)
    os.system('clear')
    print('\n=== Login ===\n')
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
        print("\n=== Login successful! ===\n")
        return True, email, key, iv, salt, user_id, cipher_mode, hash_type
    else:
        print("\n=== Invalid email or password! ===\n")
        return None


def loggedFlow(email, key, iv, salt, user_id, cipher_mode, hash_type):  # Añade cipher_mode como argumento
    while True:
        time.sleep(0.5)
        os.system('clear')
        print('\n=== Welcome user ' + email + ' ===\n')
        print("1. Insert a new register")
        print("2. List registers")
        print("3. Logout")
        choice = input("Enter your choice: ")

        if choice == "1":
            insertNewRegister(email, key, iv, salt, user_id,
                              cipher_mode, hash_type)  # Pasa cipher_mode

        elif choice == "2":
            # Pasa cipher_mode aquí también
            listRegisters(email, key, iv, salt, user_id, cipher_mode, hash_type)

        elif choice == "3":
            main()
        else:
            print("Invalid choice. Please try again.")


def listRegisters(email, key, iv, salt, user_id, cipher_mode, hash_type):
    try:
        with open(REGISTER_PATH+user_id+".txt", "r") as file:
            print("\n--- LIST OF DESCRIPTIONS ---\n")
            i = 0
            for line in file:
                i = i + 1
                print('\n=== Entry ' + str(i) + ' ===\n')
                stored_timestamp, stored_ciphertext, stored_user_id, stored_hmac, signature = line.strip().split(":")
                if cipher_mode == 'CBC':
                    cipher = AES.new(key, AES.MODE_CBC, iv) 
                    original_description = unpad(cipher.decrypt(b64decode(stored_ciphertext)), AES.block_size).decode()
                elif cipher_mode == 'CTR':
                    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
                    original_description = cipher.decrypt(b64decode(stored_ciphertext)).decode()
                               
                now = datetime.fromtimestamp(float(stored_timestamp))

                print(original_description)
                print(f"\nDate: {now}")
                print("HMAC Validity: " + "Válido" if hmac.compare_digest(stored_hmac, generate_mac(key, original_description, hash_type)) else "Não válido")
                
                #   RSA Signature validation
                try:
                    f = open('pubkeys/' + email + '_public_key.pem', "rb")
                    pubkey = RSA.importKey(f.read())
                    f.close()
                    hash = returnHash(original_description, hash_type)
                    verifier = PKCS1_v1_5.new(pubkey)
                    if verifier.verify(hash, b64decode(signature)):
                        print("Signature is authentic")
                    else:
                        print("Signature is not authentic")
                except:
                   print("Couldn't verify signature!") 
                  
                 
            input('Press any key to continue...\n')   
    except FileNotFoundError:
        print("No registers found") 
    #except ValueError:
    #    print("Error during the decryption")
    return


def returnHash(message, hash_type):
    if hash_type == 'SHA256':
        hash = SHA256.new(message.encode())
    elif hash_type == 'SHA512':
        hash = SHA512.new(message.encode())
    else:
        raise ValueError('Something went wrong during hashing!')
    return hash

def insertNewRegister(email, key, iv, salt, user_id, cipher_mode, hash_type):
    try:
        description = input("Enter your description: ")
        now = datetime.now()
        now_timestamp = datetime.timestamp(now)
        new_hmac = generate_mac(key, description, hash_type)
        
        #   Sign the file using RSA
        try: 
            print("\n=== Signing message using your private key! ===\n")
            f = open(email + '_private_key.pem', "rb")
            privkey = RSA.importKey(f.read())
            f.close()
            hash = returnHash(description, hash_type)
            signer = PKCS1_v1_5.new(privkey)
            signature = signer.sign(hash)
        except Exception as e:
            print("\n=== Error opening key! Check filename, ex: 'yourmail'_private_key.pem ===\n")
            input("Press any key to continue...")
            return
        

        if cipher_mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            ciphertext = cipher.encrypt(pad(description.encode(), AES.block_size))
            aux = f"{now_timestamp}:{b64encode(ciphertext).decode()}:{user_id}:{new_hmac}:{b64encode(signature).decode()}\n"
        elif cipher_mode == 'CTR':
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
            ciphertext = cipher.encrypt(description.encode())
            aux = f"{now_timestamp}:{b64encode(ciphertext).decode()}:{user_id}:{new_hmac}:{b64encode(signature).decode()}\n"

        with open(REGISTER_PATH+user_id+".txt", "a") as file:
            file.write(aux)
            file.close()
        print("Insertion successful!")
        input("Press any key to continue...")
    except Exception as e:
        print("Something went wrong during the process! Nothing was done.\n")
        print(e)
        input("Press any key to continue...")

    


def main():
    while True:
        time.sleep(0.5)
        os.system('clear')
        print('=== Welcome to CANTTOUCHME ===\n')
        print("1. Register")
        print("2. Login")
        print("3. Exit\n")
        choice = input("Enter your choice: ")

        if choice == "1":
            register()
        elif choice == "2":
            login_result = login()  # <-- Aquí está la corrección
            if login_result is not None:  # Si login fue exitoso
                success, email, key, iv, salt, user_id, cipher_mode, hash_type = login_result
                # <-- Aquí está la corrección
                loggedFlow(email, key, iv, salt, user_id, cipher_mode, hash_type)
        elif choice == "3":
            confirmation = input('\n=== Any remaining private keys will be deleted for security purposes! Are you sure you want to exit? y/N ===\n')
            if confirmation == 'y':
                privatekey_list = glob.glob('*_private_key.pem')
                for file in privatekey_list:
                    try:
                        os.remove(file)
                    except:
                        print('Error while deleting files! Something went wrong...')
                        time.sleep(1)
                        os.system('clear')
                        exit(0)
                input('Files deleted successfully! Press any key to continue...')
                os.system('clear')
                exit(0)
            else: main()
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
