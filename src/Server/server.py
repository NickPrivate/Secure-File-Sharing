'''import os'''
from prettytable import PrettyTable

import socket
import hashlib
import sqlite3
import threading

HOST = '127.0.0.1'
PORT = 9999

def domain_handle(client_socket, cur, user_id):
    while True:
        client_socket.send("To upload files please enter your domain name (IP Address): ".encode())
        domain = client_socket.recv(1024).decode().strip()
        client_socket.send("Please enter your port number: ".encode())
        port = client_socket.recv(1024).decode().strip()

        try:
            port = int(port)
            if not 0 < port < 65536:
                raise ValueError("Port number must be between 1 and 65535")
        except ValueError as e:
            client_socket.send(f"Invalid port number: {e}\n".encode())
            continue

        cur.execute("SELECT * FROM Peers WHERE user_id=?", (user_id,))
        if cur.fetchone():
            cur.execute("UPDATE Peers SET domain_name=?, port=? WHERE user_id=?", (domain, port, user_id))
            break
        else:
            cur.execute("INSERT INTO Peers (user_id, domain_name, port) VALUES (?, ?, ?)", (user_id, domain, port))
            break
    cur.connection.commit()
    client_socket.send("Domain and port updated successfully!\n".encode())
    print(f"UserID: {user_id} | Domain: {domain} | Port: {port}")


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
            user_id = cur.lastrowid
            cur.execute("INSERT INTO Peers (user_id, domain_name, port) VALUES (?, NULL, NULL)", (user_id,))
            cur.connection.commit()
            client_socket.send("Registration successful!\n".encode())
            print(f"UserID: {user_id} | Registered Username: {username} | Registered Password hash: {password}")
            return user_id


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
        result = cur.fetchone()
        if result: 
            user_id = result[0]
            client_socket.send("Login Successful!\n".encode())
            print(f"UserID: {user_id} | Registered Username: {username} | Registered Password hash: {password}")
            return user_id
        else:
            client_socket.send("Login Failed. Try again.\n".encode())


def upload_files(client_socket, cur, user_id):
    while True:
        client_socket.send("Enter the number of files you want to upload: ".encode())
        num_of_files = client_socket.recv(1024).decode().strip()

        if not num_of_files.isdigit():
            client_socket.send("Error: enter a number".encode())
            continue

        num_of_files = int(num_of_files)
        for i in range (1, num_of_files + 1):
            client_socket.send(f"Enter the name of file {i}:".encode())
            file_name = client_socket.recv(1024).decode().strip()
            if not file_name:
                client_socket.send("Error file cannot be empty\n".encode())
                continue

            client_socket.send(f"Enter the keyword of file {i}:".encode())
            keyword_name = client_socket.recv(1024).decode().strip()
            if not keyword_name:
                client_socket.send("Error the keyword cannot be empty\n".encode())
                continue

            cur.execute("INSERT INTO Files (file_name, keyword, peer_id) VALUES (?, ?, ?)", (file_name, keyword_name, user_id))

        client_socket.send("Are you finished sending files? Type Y/N: ".encode())

        y_or_no = client_socket.recv(1024).decode().strip()

        if y_or_no.lower() == "y":
            cur.connection.commit()
            client_socket.send("File upload completed.\n".encode())
            print("FILE UPLOAD SUCCESS")
            break
        else:
            continue


def user_query(client_socket, cur, user_id):
    client_socket.send("How many files do you want to query?: ".encode())
    number_of_files = client_socket.recv(1024).decode().strip()

    if not number_of_files.isdigit() or int(number_of_files) > 10:
        client_socket.send("Error, enter a whole number less than 10\n".encode())
        return

    number_of_files = int(number_of_files)
    keyword_list = []

    for i in range(1, number_of_files + 1):
        client_socket.send(f"Enter the Keyword for file {i}: ".encode())
        keyword = client_socket.recv(1024).decode().strip()
        if keyword:
            keyword_list.append(keyword)

    if not keyword_list:
        client_socket.send("No valid keywords entered.\n".encode())
        return

    table = PrettyTable(["File Name", "Keyword", "Domain Name", "Port", "Uploaded by"])
    any_results = False

    for keyword in keyword_list:
        cur.execute("""
                    SELECT Files.file_name, Files.keyword, Peers.domain_name, Peers.port, Users.username 
                    FROM Files
                    JOIN Peers ON Files.peer_id = Peers.user_id 
                    JOIN Users ON Peers.user_id = Users.user_id 
                    WHERE Files.keyword = ? AND Users.user_id = ?""",
                    (keyword, user_id))
        results = cur.fetchall()
        if results:
            any_results = True
            for result in results:
                table.add_row(result)
        else:
            table.add_row([None, keyword, None, None, "No results found"])

    if any_results:
        client_socket.send(b"\n" + table.get_string().encode() + b"\n\n")
    else:
        client_socket.send("No results found for any keywords.\n".encode())

    print(f"UserID: {user_id} Queried {number_of_files} {'files' if number_of_files > 1 else 'file'}")


def handle_client(client_socket, user_id = None):
    conn = sqlite3.connect("indexing_server.db")
    cur = conn.cursor()

    try:
        menu = ("Welcome to Secure File Sharing\n"
                "------------------------------\n"
                "Type 1 to register or type 2 to login\n"
                "1 - Register\n"
                "2 - Login\n")

        while True:
            client_socket.send(menu.encode())
            message = client_socket.recv(1024).decode()
            if not message:
                continue
            elif message == '1':
                user_id = handle_registration(client_socket, cur)
                break
            elif message == '2':
                user_id = handle_login(client_socket, cur)
                break
            else:
                client_socket.send("Please enter 1 or 2\n".encode())
                continue

        menu_dashboard = ("\nWelcome to The Dashboard\n"
                "------------------------------\n"
                "Type a number 1-5 to continue\n"
                "1 - Upload Files\n"
            
            # TODO --------------
            # Fix the bug when querying other people's files

                "2 - Query\n"



                "3 - Send Files\n"
                "4 - Request Files\n"
                "5 - Quit\n")

        while True:
            client_socket.send(menu_dashboard.encode())
            message = client_socket.recv(1024).decode().strip()
            if message == '1':
                domain_handle(client_socket, cur, user_id)
                upload_files(client_socket, cur, user_id)
                continue
            elif message == '2':
                user_query(client_socket, cur, user_id)
                continue

            elif message == '3':
                client_socket.send("Are you sure you want to send files? You will be disconnected from the indexing server Y/N".encode())
                message = client_socket.recv(1024).decode().strip()
                if message.lower() == 'y':
                    client_socket.send("Entering File Send Mode".encode())
                    client_socket.close()
                    conn.close()
                    break
                else:
                    continue

            elif message == '4':
                client_socket.send("Are you sure you want to request files? You will be disconnected from the indexing server Y/N".encode())
                message = client_socket.recv(1024).decode().strip()
                if message.lower() == 'y':
                    client_socket.send("Entering File Request Mode".encode())
                    client_socket.close()
                    conn.close()
                    break
                else:
                    continue

            elif message == '5':
                client_socket.send("__user_quits__".encode())
                break
            else:
                client_socket.send("Please enter 1 or 2\n".encode())
                continue
    finally:
        print(f"UserID: {user_id} | Disconnected")
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
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()
