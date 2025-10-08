import sqlite3
import os

def migrate_users_table():
    db_path = os.path.join(os.path.dirname(__file__), 'users.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Step 1: Rename old table
    cursor.execute("ALTER TABLE users RENAME TO users_old;")

    # Step 2: Create new table with UNIQUE constraint
    cursor.execute("""
        CREATE TABLE users (
            Username TEXT UNIQUE,
            Password BLOB,
            Key BLOB,
            RESULT TEXT
        );
    """)

    # Step 3: Copy data over, deduplicating by Username
    cursor.execute("""
        INSERT INTO users (Username, Password, Key, RESULT)
        SELECT Username, Password, Key, RESULT
        FROM users_old
        GROUP BY Username;
    """)

    # Step 4: Drop old table
    cursor.execute("DROP TABLE users_old;")

    conn.commit()
    cursor.close()
    conn.close()
    print("Migration complete. 'Username' is now UNIQUE.")

migrate_users_table()