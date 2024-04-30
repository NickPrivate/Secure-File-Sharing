import sqlite3
from prettytable import PrettyTable
conn = sqlite3.connect('indexing_server.db')
cursor = conn.cursor()

def init_db():

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
def get_all_tables():
    conn = sqlite3.connect('indexing_server.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM Users")
    x = PrettyTable()
    x.field_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        x.add_row(row)
    print("Users Table:")
    print(x)

    cursor.execute("SELECT * FROM Peers")
    y = PrettyTable()
    y.field_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        y.add_row(row)
    print("\nPeers Table:")
    print(y)

    cursor.execute("SELECT * FROM Files")
    z = PrettyTable()
    z.field_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        z.add_row(row)
    print("\nFiles Table:")
    print(z)

    conn.commit()
    conn.close()

def reset_database():

    cursor.execute("DROP TABLE IF EXISTS Files")
    cursor.execute("DROP TABLE IF EXISTS Peers")
    cursor.execute("DROP TABLE IF EXISTS Users")

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

    conn.commit()
    conn.close()
    print("Database has been reset.")

reset_database()
get_all_tables()
