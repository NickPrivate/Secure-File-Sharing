import socket
import time
import os
import tqdm

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature

FATAL_ERROR = "Fatal Error, Your keys are not unique, Restart program"
FILE_SEND_STRING = "Entering File Send Mode"
FILE_REQUEST_STRING = "Entering File Request Mode"
QUIT_STRING = "__user_quits__"
FILE_KW = "Enter keyword of file"

HOST = '127.0.0.1'
PORT = 9999

def sign_data_rsa(private_key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def sign_data_dsa(private_key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(
        data,
        hashes.SHA256()
    )
    return signature

def verify_signature_rsa(public_key, signature, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        print("Verification failed: Invalid signature")
    except Exception as e:
        print(f"Verification failed: {e}")
    return False

def verify_signature_dsa(public_key, signature, data):
    if isinstance(data, str):
        data = data.encode('utf-8')

    try:
        public_key.verify(
            signature,
            data,
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        print("Verification failed: Invalid DSA signature")
    except Exception as e:
        print(f"Verification failed: {e}")
    return False


def generate_aes_key_and_nonce():
    aes_key = get_random_bytes(16)
    nonce = get_random_bytes(16)
    return aes_key, nonce

def encrypt_aes_key(aes_key, nonce, senders_public_pem):
    try:
        senders_public_key = serialization.load_pem_public_key(
            senders_public_pem.encode('utf-8')
        )

        if not isinstance(senders_public_key, rsa.RSAPublicKey):
            raise ValueError("Provided public key is not an RSA public key. Encryption is not supported.")

        data_to_encrypt = aes_key + nonce

        encrypted_aes_key = senders_public_key.encrypt(
            data_to_encrypt,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_aes_key
    except UnsupportedAlgorithm:
        raise ValueError("Unsupported key type. Only RSA keys are supported for encryption.")

def decrypt_aes_key(encrypted_aes_key_and_nonce, private_key_pem):

    private_key = load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("The provided key is not an RSA private key.")

    decrypted_data = private_key.decrypt(
        encrypted_aes_key_and_nonce,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_key_length = 16
    nonce_length = 16

    aes_key = decrypted_data[:aes_key_length]
    nonce = decrypted_data[aes_key_length:aes_key_length + nonce_length]

    return aes_key, nonce

def signature_choice():
    while True:
        print("Choose the algorithm for signing:\n1 - RSA\n2 - DSA\n3 - Both")
        choice = input().strip()

        if choice == '1':
            return choice
        elif choice == '2':
            return choice
        elif choice == '3':
            return choice
        else:
            print("Inalid input, please try again")

def receive_full_message(sock):
    buffer = []
    while True:
        part = sock.recv(1024)
        buffer.append(part)
        if len(part) < 1024:
            break
    return b''.join(buffer)


def generate_dsa_keys():
    private_key = dsa.generate_private_key(
        key_size=2048
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return  pem_public_key.decode('utf-8'), pem_private_key.decode('utf-8')

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return  pem_public.decode('utf-8'), pem_private.decode('utf-8')

def generated_and_save():

    rsa_pub_path = 'rsa_public.pem'
    rsa_priv_path = 'rsa_private.pem'
    dsa_pub_path = 'dsa_public.pem'
    dsa_priv_path = 'dsa_private.pem'

    RSApublic_key, RSAprivate_key = generate_rsa_keys()
    DSApublic_key, DSAprivate_key = generate_dsa_keys()

    with open(rsa_pub_path, 'w') as f:
        f.write(RSApublic_key)
    with open(dsa_pub_path, 'w') as f:
        f.write(DSApublic_key)
    with open(rsa_priv_path, 'w') as f:
        f.write(RSAprivate_key)
    with open(dsa_priv_path, 'w') as f:
        f.write(DSAprivate_key)

    return RSApublic_key, DSApublic_key, RSAprivate_key, DSAprivate_key

def load_or_generate_keys():
    rsa_pub_path = 'rsa_public.pem'
    rsa_priv_path = 'rsa_private.pem'
    dsa_pub_path = 'dsa_public.pem'
    dsa_priv_path = 'dsa_private.pem'

    if (
        os.path.exists(rsa_pub_path)
        and os.path.exists(dsa_pub_path)
        and os.path.exists(rsa_priv_path)
        and os.path.exists(dsa_priv_path)
        ):

        with open(rsa_pub_path, 'r') as f:
            RSApublic_key = f.read()
        with open(dsa_pub_path, 'r') as f:
            DSApublic_key = f.read()
        with open(rsa_priv_path, 'r') as f:
            RSAprivate_key= f.read()
        with open(dsa_priv_path, 'r') as f:
            DSAprivate_key = f.read()

    else:
        RSAprivate_key, RSApublic_key = generate_rsa_keys()
        DSAprivate_key, DSApublic_key = generate_dsa_keys()

        with open(rsa_pub_path, 'w') as f:
            f.write(RSApublic_key)
        with open(dsa_pub_path, 'w') as f:
            f.write(DSApublic_key)
        with open(rsa_priv_path, 'w') as f:
            f.write(RSAprivate_key)
        with open(dsa_priv_path, 'w') as f:
            f.write(DSAprivate_key)

    return RSApublic_key, DSApublic_key, RSAprivate_key, DSAprivate_key


def sender(RSApublic_key, RSAprivate_key, DSApublic_key, DSAprivate_key):
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    domain_name = '127.0.0.1'
    port = 5000

    sender_socket.bind((domain_name,port))
    sender_socket.listen(1)

    print("Waiting for a connection...")
    receiver_socket, addr = sender_socket.accept()

    try:
        print(f"Connection from {addr}")

        receiver_socket.sendall(DSApublic_key.encode())


        # Receive the receivers public key
        receivers_pub_key_rsa = receiver_socket.recv(1024).decode()

        # Generate AES KEY
        secure_aes_key, nonce = generate_aes_key_and_nonce()

        # Encrypt AES KEY and Send IT
        encrypted_aes_key = encrypt_aes_key(secure_aes_key, nonce, receivers_pub_key_rsa)
        receiver_socket.send(encrypted_aes_key)

        print("Received RSA Key")
        print("Sending Encrypted AES Key...")
        # Receive Acknowledgement
        message = receiver_socket.recv(1024).decode()


        receiver_socket.send(RSApublic_key.encode())

        print(message)
    except:
        print("Sender() Error with Key Transfer")
        receiver_socket.close()
        sender_socket.close()
        exit()

    try:
        # Get file name
        while True:
            file_name = receiver_socket.recv(1024).decode()

            if os.path.exists(file_name):
                receiver_socket.send(str(1).encode())
                break
            else:
                receiver_socket.send(str(0).encode())
                print(f"Error: {file_name} does not exist")
                continue

        message = receiver_socket.recv(1024).decode()

        print(f"Received file name: {file_name}")
        file_size = os.path.getsize(file_name)

        receiver_socket.send(str(file_size).encode())

        # Store all of the file data in the variable
        with open(file_name, "rb") as f:
            data = f.read()

        cipher = AES.new(secure_aes_key, AES.MODE_EAX, nonce)
        encrypted_file = cipher.encrypt(data)

        signature_rsa = sign_data_rsa(load_pem_private_key(RSAprivate_key.encode(), password=None), data)
        receiver_socket.send(signature_rsa)

        receiver_socket.recv(1024).decode()

        signature_dsa = sign_data_dsa(load_pem_private_key(DSAprivate_key.encode(), password=None), data)
        receiver_socket.send(signature_dsa)

        sig_received = receiver_socket.recv(1024).decode()
        print(sig_received)

        receiver_socket.sendall(encrypted_file)
        receiver_socket.send(b"<END>")
        print("Encrypted File Sent")

    except:
        print("Sender() Error Handling File")

    finally:
        receiver_socket.close()
        sender_socket.close()


def receiver(RSApublic_key, RSAprivate_key):
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    domain_name = '127.0.0.1'
    port = 5000

    try:
        receiver_socket.connect((domain_name, port))

        choice = signature_choice()

        data1 = receiver_socket.recv(597).decode()
        data2 = receiver_socket.recv(597).decode()

        senders_public_key_dsa = data1 + data2 

        # Send RSA Public key
        receiver_socket.send(RSApublic_key.encode())
        # Receive encrypted AES Key
        encrypted_aes_key = receiver_socket.recv(1024)

        # Send Acknowledgement
        receiver_socket.send("Successfully received AES Key".encode())

        # Receive Senders Public Key
        senders_public_key_rsa = receiver_socket.recv(1024)
        secure_aes_key, nonce = decrypt_aes_key(encrypted_aes_key, RSAprivate_key)

        cipher = AES.new(secure_aes_key, AES.MODE_EAX, nonce)
        print("AES Key secure transmission complete")

    except:
        print("Receiver() Error with Key Transfer")
        receiver_socket.close()
        exit()

    try:
        # Send file name to sender
        while True:
            file_name = input("Enter the name of the file you want to download:").strip()
            receiver_socket.send(file_name.encode())

            file_exists = receiver_socket.recv(1024).decode()
            if file_exists != "0":
                break
            else:
                print("Error: No file found, try again")
                continue

        receiver_socket.send("Success, File Found".encode())

        # Receive the file name and size
        file_size = receiver_socket.recv(1024).decode()
        print(f"The file size is {file_size} Bytes")

        file_name = "Transferred" + file_name
        file = open(file_name, "wb")

        done = False

        file_bytes = b""

        # Receive the signature
        signature_rsa = receiver_socket.recv(256)
        receiver_socket.send("Sending Signature 1".encode())
        signature_dsa = receiver_socket.recv(256)


        receiver_socket.send("Signature received".encode())

        done = False

        # Receive all of the bytes of the file
        print(f"File {file_name} is being received...")
        progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1000, total=int(file_size))
        while not done:
            data = receiver_socket.recv(1024)
            if file_bytes[-5:] == b"<END>":
                done = True
            else:
                file_bytes += data
            progress.update(1024)

        decrypt = cipher.decrypt(file_bytes[:-5])

        if choice == '1':
            # Verify the signature
            print("Verifying Signature...")
            if verify_signature_rsa(serialization.load_pem_public_key(senders_public_key_rsa), signature_rsa, decrypt):
                print("RSA Signature verified successfully")
                file.write(decrypt)
                print("Success, File Transfer Complete")
            else:
                print("Signature verification failed")
                print("Fatal error, canceling file transfer") 

        elif choice == '2':
            # Verify the signature
            print("Verifying Signature...")
            if verify_signature_dsa(serialization.load_pem_public_key(senders_public_key_dsa.encode()), signature_dsa, decrypt):
                print("DSA Signature verified successfully")
                file.write(decrypt)
                print("Success, File Transfer Complete")
            else:
                print("DSA Signature verification failed")
                print("Fatal error, canceling file transfer") 
        else:

            print("Verifying RSA and DSA Signatures...")
            if verify_signature_rsa(serialization.load_pem_public_key(senders_public_key_rsa), signature_rsa, decrypt):
                print("RSA Signature verified successfully")
                file.write(decrypt)
            else:
                print("Signature verification failed")
                print("Fatal error, canceling file transfer") 

            if verify_signature_dsa(serialization.load_pem_public_key(senders_public_key_dsa.encode()), signature_dsa, decrypt):
                print("DSA Signature verified successfully")
                print("GREAT NEWS!\nBoth RSA and DSA signatures verified")
                print("Success, File Transfer Complete")
                file.write(decrypt)
            else:
                print("DSA Signature verification failed")
                print("Fatal error, canceling file transfer") 

        file.close()


    except:
        print("Receiver Closed Unexpectedly")
        receiver_socket.close()
    receiver_socket.close()


def client_entry():
    while True:
        print("Before we connect to the server, do you want to update your keys?\n1 - Generate Keys\n2 - Use Existing Keys")
        key_choice = input()
        if key_choice == '1': 
            RSApublic_key, DSApublic_key, RSAprivate_key, DSAprivate_key = generated_and_save()
            break
        elif key_choice == '2':
            RSApublic_key, DSApublic_key, RSAprivate_key, DSAprivate_key = load_or_generate_keys()
            break
        else:
            continue

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        client.send(key_choice.encode())
        client.recv(1024).decode()

        client.send(RSApublic_key.encode('utf-8'))
        client.recv(1024).decode()
        client.sendall(DSApublic_key.encode('utf-8'))

        keys_sent_ack = client.recv(1024).decode()
        if keys_sent_ack == "Both Keys Received":
            print("Server acknowledged keys, proceeding...")
        else:
            print("Did not receive correct acknowledgment from server, exiting...")
            client.close()
    except:
        print("Connection Failed, Server is not Running")
        exit()

    try:
        while True:
            time.sleep(0.5)
            message = receive_full_message(client).decode()
            if (message != QUIT_STRING
                and message != FILE_SEND_STRING 
                and message != FILE_REQUEST_STRING 
                and message != FILE_KW
                and message != FATAL_ERROR
                ):

                print(message)
                while True:
                    response = input().strip()
                    if response:
                        client.send(response.encode('utf-8'))
                        break
                    else:
                        print("No input detected")
            elif message == FILE_KW:
                response = input().strip()
                client.send(response.encode('utf-8'))
            elif message == FILE_SEND_STRING:
                client.close()
                time.sleep(0.5)
                sender(RSApublic_key, RSAprivate_key, DSApublic_key, DSAprivate_key)
                time.sleep(20)
                break

            elif message == FILE_REQUEST_STRING:
                client.close()
                time.sleep(0.5)
                receiver(RSApublic_key, RSAprivate_key)
                break
            else:
                break
    finally:
        client.close()
        print("Disconnected")

client_entry()
