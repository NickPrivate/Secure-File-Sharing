from prettytable import PrettyTable

import socket
import sqlite3
import threading
import bcrypt

HOST = '127.0.0.1'
PORT = 9999

def hash_and_salt(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed

def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

def domain_handle(client_socket, cur, user_id):
    while True:
        client_socket.send("To upload files please enter your domain name (IP Address): ".encode('utf-8'))
        domain = client_socket.recv(1024).decode().strip()
        client_socket.send("Please enter your port number: ".encode('utf-8'))
        port = client_socket.recv(1024).decode().strip()

        try:
            port = int(port)
            if not 0 < port < 65536:
                raise ValueError("Port number must be between 1 and 65535")
        except ValueError as e:
            client_socket.send(f"Invalid port number: {e}\n".encode('utf-8'))
            continue

        cur.execute("SELECT * FROM Peers WHERE user_id=?", (user_id,))
        if cur.fetchone():
            cur.execute("UPDATE Peers SET domain_name=?, port=? WHERE user_id=?", (domain, port, user_id))
            break
        else:
            cur.execute("INSERT INTO Peers (user_id, domain_name, port) VALUES (?, ?, ?)", (user_id, domain, port))
            break
    cur.connection.commit()
    client_socket.send("Domain and port updated successfully!\n".encode('utf-8'))
    print(f"UserID: {user_id} | Domain: {domain} | Port: {port}")


def handle_registration(client_socket, cur, clientRSA, clientDSA):
    while True:
        client_socket.send("Enter New Username: ".encode('utf-8'))
        username = client_socket.recv(1024).decode().strip()
        if not username:
            continue
        client_socket.send("Enter New Password: ".encode('utf-8'))
        password = client_socket.recv(1024).decode().strip()
        if not password:
            continue

        hashed_password = hash_and_salt(password)

        cur.execute("SELECT * FROM Users WHERE username=?", (username,))
        if cur.fetchone() is not None:
            client_socket.send("Username already exists. Try a different username.\n".encode('utf-8'))
            continue

        cur.execute("SELECT * FROM Users WHERE RSApublickey=?", (clientRSA,))
        if cur.fetchone() is not None:
            client_socket.send("Fatal Error, Your keys are not unique, Restart program".encode('utf-8'))
            cur.close()
            client_socket.close()

        else:
            cur.execute("INSERT INTO Users (username, password, RSApublickey, DSApublickey) VALUES (?, ?, ?, ?)", (username, hashed_password, clientRSA, clientDSA))
            cur.connection.commit()
            user_id = cur.lastrowid
            cur.execute("INSERT INTO Peers (user_id, domain_name, port) VALUES (?, NULL, NULL)", (user_id,))
            cur.connection.commit()
            client_socket.send("Registration successful!\n".encode('utf-8'))
            """client_socket.send(f"Your private key is: {private_key}".encode('utf-8'))"""
            print(f"UserID: {user_id} | Registered Username: {username} | Registered Password hash: {password}")
            return user_id


def handle_login(client_socket, cur, clientRSA, clientDSA, key_choice):
    while True:
        client_socket.send("Enter Username: ".encode('utf-8'))
        username = client_socket.recv(1024).decode().strip()
        if not username:
            continue
        client_socket.send("Enter Password: ".encode('utf-8'))
        password = client_socket.recv(1024).decode().strip()
        if not password:
            continue

        cur.execute("SELECT * FROM Users WHERE username=?", (username,))
        result = cur.fetchone()

        if result == None:
            client_socket.send("Login Failed. Try again.\n".encode('utf-8'))
            continue

        stored_hash = result[2]


        if verify_password(stored_hash, password)and key_choice == '1': 
            cur.execute("UPDATE Users SET RSApublickey=?, DSApublickey=? WHERE username=?", (clientRSA, clientDSA, username))
            cur.connection.commit()
            user_id = result[0]
            client_socket.send("Login Successful && Keys Updated!\n".encode('utf-8'))
            print(f"UserID: {user_id} | Registered Username: {username} | Password Hash {stored_hash}")
            return user_id

        elif verify_password(stored_hash, password)and key_choice == '2': 
            user_id = result[0]
            client_socket.send("Login Successful!\n".encode('utf-8'))
            print(f"UserID: {user_id} | Registered Username: {username} | Registered Password hash: {password}")
            return user_id

        else:
            client_socket.send("Login Failed. Try again.\n".encode('utf-8'))


def upload_files(client_socket, cur, user_id):
    while True:
        client_socket.send("Enter the number of files you want to upload: ".encode('utf-8'))
        num_of_files = client_socket.recv(1024).decode().strip()

        if not num_of_files.isdigit():
            client_socket.send("Error: enter a number".encode('utf-8'))
            continue

        num_of_files = int(num_of_files)
        for i in range (1, num_of_files + 1):
            client_socket.send(f"Enter the name of file {i}:".encode('utf-8'))
            file_name = client_socket.recv(1024).decode().strip()
            if not file_name:
                client_socket.send("Error file cannot be empty\n".encode('utf-8'))
                continue

            client_socket.send(f"Enter the keyword of file {i}:".encode('utf-8'))
            keyword_name = client_socket.recv(1024).decode().strip()
            if not keyword_name:
                client_socket.send("Error the keyword cannot be empty\n".encode('utf-8'))
                continue

            cur.execute("INSERT INTO Files (file_name, keyword, peer_id) VALUES (?, ?, ?)", (file_name, keyword_name, user_id))

        client_socket.send("Are you finished sending files? Type Y/N: ".encode('utf-8'))

        y_or_no = client_socket.recv(1024).decode().strip()

        if y_or_no.lower() == "y":
            cur.connection.commit()
            client_socket.send("File upload completed.\n".encode('utf-8'))
            print("FILE UPLOAD SUCCESS")
            break
        else:
            continue


def user_query(client_socket, cur, user_id):
    client_socket.send("How many files do you want to query?: ".encode('utf-8'))
    number_of_files = client_socket.recv(1024).decode().strip()

    if not number_of_files.isdigit() or int(number_of_files) > 10:
        client_socket.send("Error, enter a whole number less than 10\n".encode('utf-8'))
        return

    number_of_files = int(number_of_files)
    keyword_list = []

    for i in range(1, number_of_files + 1):
        client_socket.send(f"Enter the Keyword for file {i}: ".encode('utf-8'))
        keyword = client_socket.recv(1024).decode().strip()
        if keyword:
            keyword_list.append(keyword)

    if not keyword_list:
        client_socket.send("No valid keywords entered.\n".encode('utf-8'))
        return

    table = PrettyTable(["File Name", "Keyword", "Domain Name", "Port", "Uploaded by", "RSA Public Key", "DSA Public Key"])
    any_results = False

    for keyword in keyword_list:
        cur.execute("""
                    SELECT Files.file_name, Files.keyword, Peers.domain_name, Peers.port, Users.username, Users.RSApublickey, Users.DSApublickey 
                    FROM Files
                    JOIN Peers ON Files.peer_id = Peers.user_id 
                    JOIN Users ON Peers.user_id = Users.user_id 
                    WHERE Files.keyword = ?""",
                    (keyword,))
        results = cur.fetchall()
        if results:
            any_results = True
            for result in results:
                table.add_row(result)
        else:
            table.add_row([None, keyword, None, None, "No results found", None, None])

    if any_results:
        client_socket.send(b"\n" + table.get_string().encode('utf-8') + b"\n\n")
    else:
        client_socket.send("No results found for any keywords.\n".encode('utf-8'))

    print(f"UserID: {user_id} Queried {number_of_files} {'files' if number_of_files > 1 else 'file'}")


def receive_full_message(sock):
    sock.settimeout(0.1)
    buffer = []
    try:
        while True:
            part = sock.recv(1024)
            if not part:
                break
            buffer.append(part)
    except socket.timeout:
        print("Data Received")
    finally:
        sock.settimeout(None)
    return b''.join(buffer)


def handle_client(client_socket, user_id=None):
    conn = sqlite3.connect("indexing_server.db")
    cur = conn.cursor()

    key_choice = client_socket.recv(1024).decode()
    client_socket.send("Key choice received".encode())


    RSA_key = client_socket.recv(1024).decode('utf-8')
    client_socket.send("RSA Key Received".encode('utf-8'))
    DSA_key = receive_full_message(client_socket).decode('utf-8')
    client_socket.send("Both Keys Received".encode('utf-8'))

    if RSA_key is None or DSA_key is None:
        print("Failed to get keys")
        client_socket.close()
        return
    try:
        menu = ("Welcome to Secure File Sharing\n"
                "------------------------------\n"
                "Type 1 to register or type 2 to login\n"
                "1 - Register\n"
                "2 - Login\n")

        while True:
            client_socket.send(menu.encode('utf-8'))
            message = client_socket.recv(1024).decode()
            if not message:
                continue
            elif message == '1':
                user_id = handle_registration(client_socket, cur, RSA_key, DSA_key)
                break
            elif message == '2':
                user_id = handle_login(client_socket, cur, RSA_key, DSA_key, key_choice)
                break
            else:
                client_socket.send("Please enter 1 or 2\n".encode('utf-8'))
                continue

        menu_dashboard = ("\nWelcome to The Dashboard\n"
                "------------------------------\n"
                "Type a number 1-5 to continue\n"
                "1 - Upload Files\n"
                "2 - Query\n"
                "3 - Send Files\n"
                "4 - Request Files\n"
                "5 - Quit\n")

        while True:
            client_socket.send(menu_dashboard.encode('utf-8'))
            message = client_socket.recv(1024).decode().strip()
            if message == '1':
                domain_handle(client_socket, cur, user_id)
                upload_files(client_socket, cur, user_id)
                continue
            elif message == '2':
                user_query(client_socket, cur, user_id)
                continue

            elif message == '3':
                client_socket.send("Are you sure you want to send files? You will be disconnected from the indexing server Y/N".encode('utf-8'))
                message = client_socket.recv(1024).decode().strip()
                if message.lower() == 'y':
                    client_socket.send("Entering File Send Mode".encode('utf-8'))
                    client_socket.close()
                    conn.close()
                    break
                else:
                    continue

            elif message == '4':
                client_socket.send("Are you sure you want to request files? You will be disconnected from the indexing server Y/N".encode('utf-8'))
                message = client_socket.recv(1024).decode().strip()
                if message.lower() == 'y':
                    client_socket.send("Entering File Request Mode".encode('utf-8'))
                    client_socket.close()
                    conn.close()
                    break
                else:
                    continue

            elif message == '5':
                client_socket.send("__user_quits__".encode('utf-8'))
                break
            else:
                client_socket.send("Please enter 1 or 2\n".encode('utf-8'))
                continue
    finally:
        print(f"\nUserID: {user_id} | Disconnected\n")
        client_socket.close()
        conn.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Listening on port {PORT}...")
    while True:
        client_socket, addr = server_socket.accept()
        print(f"\nConnected to {addr}\n")
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()
