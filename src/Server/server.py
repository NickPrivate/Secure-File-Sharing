import socket
import hashlib
import sqlite3

HOST = '127.0.0.1'
PORT = 9999

def handle_login(client_socket):
    client_socket.send("Enter Username: ".encode())
    username = client_socket.recv(1024).decode().strip()
    client_socket.send("Enter Password: ".encode())
    password = client_socket.recv(1024).decode().strip()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    print(f"Received username: {username}")
    print(f"Received hashed password: {hashed_password}")

    conn = sqlite3.connect("indexing_server.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM Users WHERE username=? AND password=?", (username, hashed_password))

    if cur.fetchone():
        client_socket.send("Login Successful!".encode())
    else:
        client_socket.send("Login Failed".encode())

    client_socket.close()
    conn.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Listening on port {PORT}...")
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connected to {addr}")
        handle_login(client_socket)

start_server()

