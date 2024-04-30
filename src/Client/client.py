import socket
import time

HOST = '127.0.0.1'
PORT = 9999
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
except:
    print("Connection Failed, Server is not Running")
    exit()

try:
    while True:
        time.sleep(0.1)
        message = client.recv(1024).decode()
        if message:
            print(message)
            response = input()
            client.send(response.encode())
        else:
            break
finally:
    client.close()
    print("Disconnected from server.")
