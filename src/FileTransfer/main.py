import socket
import os
import tqdm

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def receive_full_message(sock):
    buffer = []
    while True:
        part = sock.recv(1024)
        buffer.append(part)
        if len(part) < 1024:
            break
    return b''.join(buffer)

def generate_aes_key():
    aes_key = get_random_bytes(16)
    return aes_key

def encrypt_aes_key(aes_key, senders_public_pem):
    try:
        senders_public_key = serialization.load_pem_public_key(
            senders_public_pem.encode('utf-8')
        )

        if not isinstance(senders_public_key, rsa.RSAPublicKey):
            raise ValueError("Provided public key is not an RSA public key. Encryption is not supported.")

        encrypted_aes_key = senders_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_aes_key
    except UnsupportedAlgorithm:
        raise ValueError("Unsupported key type. Only RSA keys are supported for encryption.")

def decrypt_aes_key(encrypted_aes_key, private_key_pem):

    private_key = load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("The provided key is not an RSA private key.")

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

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

        # 2 Receive the receivers public key
        message = receiver_socket.recv(1024).decode()

        # 3 Generate AES KEY
        secure_aes_key = generate_aes_key()

        # 4 Encrypt AES KEY and Send IT
        encrypted_aes_key = encrypt_aes_key(secure_aes_key, message)
        receiver_socket.send(encrypted_aes_key)

        print("Received RSA Key")
        print("Sending Encrypted AES Key...")
        # 7 Receive Acknowledgement
        message = receiver_socket.recv(1024).decode()


        file_name = input("Enter the name of the file you want to download:")
        file_size = os.path.getsize(file_name)

        with open(file_name, "rb") as f:
            data = f.read()

        cipher = AES.new(secure_aes_key, AES.MODE_EAX)
        encrypted_file = cipher.encrypt(data)

        # 8 Encrypt the file with AES and send it 
        receiver_socket.send("file.txt".encode())
        receiver_socket.send(str(file_size).encode())
        receiver_socket.sendall(encrypted_file)
        receiver_socket.send(b"<END>")
        print(encrypted_file)
        print(message)

    finally:
        receiver_socket.close()
        sender_socket.close()


def receiver():
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    domain_name = '127.0.0.1'
    port = 5000

    try:
        receiver_socket.connect((domain_name, port))

        # 1 Send RSA Public key
        receiver_socket.send(RSApublic_key.encode())
        # 5 Receive encrypted AES Key
        encrypted_aes_key = receiver_socket.recv(1024)

        # 6 Send Acknowledgement
        receiver_socket.send("Successfully received AES Key".encode())

        secure_aes_key = decrypt_aes_key(encrypted_aes_key, RSAprivate_key)

        print("AES Key secure transmission complete")


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
        exit()
    elif choice == '2':
        receiver()
        print("THAT'S ALL FOLKS")
        exit()
    else:
        continue

