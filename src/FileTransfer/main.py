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

def sign_data(private_key, data):
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

def verify_signature(public_key, signature, data):
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

def receive_full_message(sock):
    buffer = []
    while True:
        part = sock.recv(1024)
        buffer.append(part)
        if len(part) < 1024:
            break
    return b''.join(buffer)

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

    return pem_private_key.decode('utf-8'), pem_public_key.decode('utf-8')

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

    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

RSAprivate_key, RSApublic_key = generate_rsa_keys()
DSAprivate_key, DSApublic_key = generate_dsa_keys()


def sender():
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    domain_name = '127.0.0.1'
    port = 5000

    sender_socket.bind((domain_name,port))
    sender_socket.listen(1)

    print("Waiting for a connection...")
    receiver_socket, addr = sender_socket.accept()

    try:
        print(f"Connection from {addr}")

        # Receive the receivers public key
        receivers_pub_key = receiver_socket.recv(1024).decode()

        # Generate AES KEY
        secure_aes_key, nonce = generate_aes_key_and_nonce()

        # Encrypt AES KEY and Send IT
        encrypted_aes_key = encrypt_aes_key(secure_aes_key, nonce, receivers_pub_key)
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

        signature = sign_data(load_pem_private_key(RSAprivate_key.encode(), password=None), data)

        # Encrypt the file with AES and send it 
        receiver_socket.send(signature)

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


def receiver():
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    domain_name = '127.0.0.1'
    port = 5000

    try:
        receiver_socket.connect((domain_name, port))

        # Send RSA Public key
        receiver_socket.send(RSApublic_key.encode())
        # Receive encrypted AES Key
        encrypted_aes_key = receiver_socket.recv(1024)

        # Send Acknowledgement
        receiver_socket.send("Successfully received AES Key".encode())

        # Receive Senders Public Key
        senders_public_key = receiver_socket.recv(1024)
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

        file_name = "Received" + file_name
        file = open(file_name, "wb")

        done = False

        file_bytes = b""

        # Receive the signature
        signature = receiver_socket.recv(256)

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

        # Verify the signature
        print("Verifying Signature...")
        if verify_signature(serialization.load_pem_public_key(senders_public_key), signature, decrypt):
            print("RSA Signature verified successfully")
            file.write(decrypt)
            print("Success, File Transfer Complete")
        else:
            print("Signature verification failed")
            print("Fatal error, canceling file transfer") 

        file.close()


    except:
        print("Receiver Closed Unexpectedly")
        receiver_socket.close()
    receiver_socket.close()

while True:

    print("Sender or receiver")
    print("1 - Sender (server)")
    print("2 - Receiver (requester)")

    choice = input()


    if choice == '1':
        sender()
        print("THAT'S ALL FOLKS")
        time.sleep(20)
        exit()
    elif choice == '2':
        receiver()
        print("THAT'S ALL FOLKS")
        exit()
    else:
        continue

