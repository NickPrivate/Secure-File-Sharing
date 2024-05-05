from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

import os
import socket
import time

file_send_string = "Entering File Send Mode"
file_request_string = "Entering File Request Mode"
quit_string = "__user_quits__"
file_kw = "Enter keyword of file"

HOST = '127.0.0.1'
PORT = 9999

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


def load_or_generate_keys():
    rsa_pub_path = 'rsa_public.pem'
    rsa_priv_path = 'rsa_private.pem'
    dsa_pub_path = 'dsa_public.pem'
    dsa_priv_path = 'dsa_private.pem'
    '''if os.path.exists(rsa_pub_path) and os.path.exists(dsa_pub_path):
        with open(rsa_pub_path, 'r') as f:
            RSApublic_key = f.read()
        with open(dsa_pub_path, 'r') as f:
            DSApublic_key = f.read()'''
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

RSApublic_key, DSApublic_key, RSAprivate_key, DSAprivate_key = load_or_generate_keys()

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    client.send(RSApublic_key.encode('utf-8'))
    client.recv(1024).decode()
    client.send(DSApublic_key.encode('utf-8'))

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
        if message != quit_string and message != file_send_string and message != file_request_string and message != file_kw:
            print(message)
            while True:
                response = input().strip()
                if response:
                    client.send(response.encode('utf-8'))
                    break
                else:
                    print("No input detected")
        elif message == file_kw:
            response = input().strip()
            client.send(response.encode('utf-8'))
        elif message == file_send_string:
            # TODO Create a function receiver() for the client that sends the file
            print("THIS IS WHERE SEND LOGIC GOES")
            break
        elif message == file_request_string:
            # TODO Create a function sender() for the client that receives the senders file 
            print("THIS IS WHERE REQUEST LOGIC GOES")
            break
        else:
            break
finally:
    client.close()
    print("Disconnected from server.")

def sender():
    pass

def receiver():
    pass
