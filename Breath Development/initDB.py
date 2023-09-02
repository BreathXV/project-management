import sqlite3

def initialize_database():
    try:
        conn = sqlite3.connect('./database.db')
        cursor = conn.cursor()

        # Create the 'users' table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')

        # Create the 'projects' table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY,
                project_name TEXT NOT NULL,
                project_tag TEXT,
                assignee TEXT NOT NULL,
                project_description TEXT,
                project_payment REAL,
                project_due_date DATETIME, -- Use DATETIME data type for datetime
                project_platform TEXT
            )
        ''')

        conn.commit()
        print("Database tables initialized successfully.")
    except sqlite3.Error as e:
        print("Error initializing database tables:", e)
    finally:
        conn.close()

initialize_database()