import json
import sqlite3
import tkinter as tk
import logging
from tkinter import messagebox as mb
from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Cipher import AES
import os
import sys

# Logging setup
logging.basicConfig(filename='activity.log',
                    level=logging.DEBUG,
                    format='%(asctime)s : %(levelname)s : %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# Determine correct path for DB
def get_db_path():
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, 'users.db')

# Create table with UNIQUE constraint
def ensure_table():
    db_file = get_db_path()
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            Username TEXT UNIQUE,
            Password BLOB,
            Key BLOB,
            RESULT TEXT
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()

# Insert or replace user data
def upsert_user(username, password, key, result):
    try:
        db_file = get_db_path()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO users (Username, Password, Key, RESULT)
            VALUES (?, ?, ?, ?);
        """, (username, password, key, result))
        conn.commit()
        cursor.close()
        conn.close()
        logging.info(f"Upserted user: {username}")
        return True
    except sqlite3.Error as error:
        logging.exception("SQLite upsert failed")
        mb.showerror('Failed', f'SQLite error: {error}')
        return False

# Check for empty fields
def user_pass_check_empty():
    if UE.get() and PE.get():
        return True
    elif not UE.get() and PE.get():
        logging.error("Input is required for Username")
        mb.showerror('Failed', 'Input is required for Username')
    elif not PE.get() and UE.get():
        logging.error("Input is required for Password")
        mb.showerror('Failed', 'Input is required for Password')
    else:
        logging.error("Input is required for Username and Password")
        mb.showerror('Failed', 'Input is required for Username and Password')
    return False

# Encrypt and save data
def set_data_to_db():
    try:
        if not user_pass_check_empty():
            return

        user = UE.get().casefold()
        pw = PE.get()
        key = get_random_bytes(32)

        pw_data = pw.encode('utf-8')
        cipher_encrypt = AES.new(key, AES.MODE_CFB)
        ct_bytes = cipher_encrypt.encrypt(pw_data)
        iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        ciphered_data = ct_bytes

        success = upsert_user(user, ciphered_data, key, result)
        if success:
            mb.showinfo('Success', f'Data saved for user: {user}')

        UE.delete(0, tk.END)
        PE.delete(0, tk.END)

    except Exception as e:
        logging.exception("Unexpected error in set_data_to_db")
        mb.showerror('Failed', f'Unexpected error: {e}')

######################################################################################################################
# GUI Layout
######################################################################################################################

win = tk.Tk()
win.geometry('300x250')
win.resizable(0, 0)
bullet = "\u2022"

UL = tk.Label(win, text="Username: ")
UE = tk.Entry(win)

PL = tk.Label(win, text="Password: ")
PE = tk.Entry(win, show=bullet)

SB = tk.Button(win, text="Submit", padx=10, command=set_data_to_db)
EB = tk.Button(win, text="Exit", padx=15, command=win.quit)

menu_bar = tk.Menu(win)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=win.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

UL.grid(row=0, column=0, padx=15, pady=40)
UE.grid(row=0, column=1, padx=15, pady=15)
PL.grid(row=1, column=0, padx=15, pady=15)
PE.grid(row=1, column=1, padx=15, pady=15)
EB.grid(row=3, column=1, columnspan=2, padx=105, pady=15)
SB.grid(row=3, column=0, columnspan=2, padx=5, pady=15)

win.title("Password Locker")
win.wm_iconbitmap("favicon.ico")
win.config(menu=menu_bar)

ensure_table()
win.mainloop()