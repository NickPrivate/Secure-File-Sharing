import socket

HOST = '127.0.0.1'
PORT = 9999

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

try:
    while True:
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
