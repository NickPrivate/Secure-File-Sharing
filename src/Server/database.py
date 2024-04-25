import sqlite3
import hashlib

def init_db():

    conn = sqlite3.connect('indexing_server.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Peers (
        user_id INTEGER PRIMARY KEY,
        domain_name TEXT,
        port INTEGER,
        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES Users(user_id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Files (
        file_id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_name TEXT NOT NULL,
        keyword TEXT NOT NULL,
        peer_id INTEGER NOT NULL,
        FOREIGN KEY (peer_id) REFERENCES Peers(user_id)
    )
    ''')

    # Sample user and peer insertion (example)
    # username1, password1 = "BigNick", hashlib.sha256("Test123".encode()).hexdigest()
    # cursor.execute("INSERT INTO Users (username, password) VALUES (?, ?)", (username1, password1))
    # user_id = cursor.lastrowid

    # Example to add a peer related to the user
    # cursor.execute("INSERT INTO Peers (user_id, domain_name, port) VALUES (?, ?, ?)", (user_id, "example.com", 8080))
   
    cursor.execute("SELECT * FROM Users")
    results = cursor.fetchall()
    print(f"Result is {results}")

    cursor.execute("SELECT * FROM Peers")
    results = cursor.fetchall()
    print(f"Result is {results}")

    conn.commit()
    conn.close()

init_db()

