import os
import sqlite3
import tkinter as tk
import logging
from tkinter import messagebox as mb
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys
import pyperclip

logging.basicConfig(filename='activity.log', level=logging.INFO,
                    format='%(asctime)s : %(levelname)s : %(message)s')


def select_all_passwords():
    PASSWORDS = {}
    try:
        sqlite_connection = sqlite3.connect(os.getenv('db'))
        cursor = sqlite_connection.cursor()
        logging.info("Connected to SQLite")

        sqlite_select_with_param = os.getenv('select_user')
        cursor.execute(sqlite_select_with_param)
        sqlite_connection.commit()
        logging.info("Python Variables read successfully into SqliteDb_developers table")
        rows = cursor.fetchall()

        # PASSWORDS = dict()
        # for row in rows:
        #     dict((row, rows) for x, y in PASSWORDS)

        cursor.close()
        print(PASSWORDS)
        if len(sys.argv) < 2:
            print('Usage: python pow.py[account] - copy account password')
            sys.exit()

        account = sys.argv[1]  # first command line arg is account name

        if account in PASSWORDS:
            pyperclip.copy(PASSWORDS[account])
            print('Password for {} copied to clipboard.'.format(account))
        else:
            print('There is no account named {}.'.format(account))

    except sqlite3.Error as error:
        logging.error("Failed to read Python variable into sqlite table", error)
        mb.showerror('Failed', 'Failed to insert Python variable into sqlite table')
    finally:
        if (sqlite_connection):
            sqlite_connection.close()
            logging.info("The SQLite connection is closed")


def insert_variable_into_table(username, password):
    try:
        sqlite_connection = sqlite3.connect(os.getenv('db'))
        cursor = sqlite_connection.cursor()
        logging.info("Connected to SQLite")
        sqlite_insert_with_param = os.getenv('insert_user')
        data_tuple = (username, password)
        cursor.execute(sqlite_insert_with_param, data_tuple)
        sqlite_connection.commit()
        logging.info("Python Variables inserted successfully into SqliteDb_developers table")

        cursor.close()

    except sqlite3.Error as error:
        logging.error("Failed to insert Python variable into sqlite table", error)
        mb.showerror('Failed', 'Failed to insert Python variable into sqlite table')
    finally:
        if (sqlite_connection):
            sqlite_connection.close()
            logging.info("The SQLite connection is closed")


def set_data_to_db():
    key_location = os.getenv('key_location')
    # Generate the key
    key = get_random_bytes(32)

    # Save the key to a file
    file_out = open(key_location, "wb")  # wb = write bytes
    file_out.write(key)
    file_out.close()
    user = UE.get()
    pw = PE.get()

    # === Encrypt ===
    # First make your data a bytes object. To convert a string to a bytes object, we can call .encode() on it
    pw_data = pw.encode('utf-8')

    # Create the cipher object and encrypt the data
    cipher_encrypt = AES.new(key, AES.MODE_CFB)
    ciphered_bytes = cipher_encrypt.encrypt(pw_data)

    # This is now our data
    iv = cipher_encrypt.iv
    ciphered_data = ciphered_bytes
    ciphered_string = ciphered_data.decode('iso-8859-1').encode('utf8')
    insert_variable_into_table(user, ciphered_string)
    # === Decrypt ===

    # Later on ... (assume we no longer have the key)
    file_in = open(key_location, "rb")  # Read bytes
    key_from_file = file_in.read()  # This key should be the same
    file_in.close()

    # Since this is a demonstration, we can verify that the keys are the same (just for proof - you don't need to do
    # this)
    assert key == key_from_file, 'Keys do not match'  # Will throw an AssertionError if they do not match

    # Create the cipher object and decrypt the data
    cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
    deciphered_bytes = cipher_decrypt.decrypt(ciphered_data)

    # Convert the bytes object back to the string
    decrypted_data = deciphered_bytes.decode('utf-8')
    print("Decrypted data:", decrypted_data)

    # === Proving the data matches ===

    # Now we prove that the original data is the same as the data we just ciphered out (running these should throw no
    # errors)
    assert pw == decrypted_data, 'Original data does not match the result'
    UE.delete(0, tk.END)
    PE.delete(0, tk.END)
    mb.showinfo('Success', 'Data Successfully Saved')


win = tk.Tk()
win.geometry('300x250')  # set window size
win.resizable(0, 0)  # fix window
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

# App Title
win.title("Password Locker")
# App Favicon
win.wm_iconbitmap("favicon.ico")
win.config(menu=menu_bar)
select_all_passwords()
win.mainloop()
