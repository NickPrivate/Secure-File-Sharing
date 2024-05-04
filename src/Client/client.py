from Crypto.Cipher import AES
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

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
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
                    client.send(response.encode())
                    break
                else:
                    print("No input detected")
        elif message == file_kw:
            response = input().strip()
            client.send(response.encode())
        elif message == file_send_string:
            # TODO Create a function for the client that sends the file
            print("THIS IS WHERE SEND LOGIC GOES")
            break
        elif message == file_request_string:
            # TODO Create a function for the client that receives the senders file 
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
