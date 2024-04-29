'''import os'''

import socket
import hashlib
import sqlite3
import threading

HOST = '127.0.0.1'
PORT = 9999

def domain_handle(client_socket,cur):
    while True:
        client_socket.send("Plese enter your domain name: ".encode())
        domain = client_socket.recv(1024).decode()
        client_socket.send("Plese enter your port number: ".encode())
        port = client_socket.recv(1024).decode()

        cur.execute("SELECT * FROM Peers WHERE domain_name=?", (domain,))
        if cur.fetchone() is not None:
            client_socket.send("Domain already taken. Try a different domain.\n".encode())

        else:
            cur.execute("INSERT INTO Peers (domain_name, port) VALUES (?, ?)", (domain, port))
            cur.connection.commit()
            client_socket.send("Domain and Port successfully sent!\n".encode())
            print(f"Registered Domain: {domain}")
            print(f"Registered Port: {port}")
            break

def handle_registration(client_socket, cur):
    while True:
        client_socket.send("Enter New Username: ".encode())
        username = client_socket.recv(1024).decode().strip()
        if not username:
            continue
        client_socket.send("Enter New Password: ".encode())
        password = client_socket.recv(1024).decode().strip()
        if not password:
            continue
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        cur.execute("SELECT * FROM Users WHERE username=?", (username,))
        if cur.fetchone() is not None:
            client_socket.send("Username already exists. Try a different username.\n".encode())
        else:
            cur.execute("INSERT INTO Users (username, password) VALUES (?, ?)", (username, hashed_password))
            cur.connection.commit()
            client_socket.send("Registration successful!\n".encode())
            print(f"Registered username: {username}")
            print(f"Registered hashed password: {hashed_password}")
            break


def handle_login(client_socket, cur):
    while True:
        client_socket.send("Enter Username: ".encode())
        username = client_socket.recv(1024).decode().strip()
        if not username:
            continue
        client_socket.send("Enter Password: ".encode())
        password = client_socket.recv(1024).decode().strip()
        if not password:
            continue
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        cur.execute("SELECT * FROM Users WHERE username=? AND password=?", (username, hashed_password))
        if cur.fetchone():
            client_socket.send("Login Successful!\n".encode())
            break
        else:
            client_socket.send("Login Failed. Try again.\n".encode())


def handle_client(client_socket):
    conn = sqlite3.connect("indexing_server.db")
    cur = conn.cursor()

    try:
        menu = ("Welcome to Secure File Sharing\n"
                "------------------------------\n"
                "Type 1 to register or type 2 to login\n"
                "1 - Register\n"
                "2 - Login\n")
        client_socket.send(menu.encode())
        
        while True:
            message = client_socket.recv(1024).decode().strip()
            if message == '1':
                handle_registration(client_socket, cur)
                domain_handle(client_socket,cur)
                break
            elif message == '2':
                handle_login(client_socket, cur)
                domain_handle(client_socket, cur)
                break
            else:
                client_socket.send("Please enter 1 or 2\n".encode())
    finally:
        client_socket.close()
        conn.close()



# Todo ------------------------
'''
def upload_files(client_socket, cur):
    while True:
        client_socket.send("Enter the number of files you want to upload: ".encode())
        num_of_files = int(client_socket.recv(1024).decode())
        for i in range(0,num_of_files):
            client_socket.send(f"Enter the name of file {i} :".encode())
            file_name = client_socket.recv(1024).decode())
            client_socket.send(f"Enter the keyword of file {i} :".encode())
            keyword_name = client_socket.recv(1024).decode())
            pass

'''

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Listening on port {PORT}...")
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connected to {addr}")
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()
