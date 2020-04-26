import json
import sqlite3
import tkinter as tk
import logging
from tkinter import messagebox as mb
from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Cipher import AES
import os

# Logging configurations
logging.basicConfig(filename='activity.log',
                    level=logging.DEBUG,
                    format='%(asctime)s : %(levelname)s : %(message)s')

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# add the handler to the root logger
logging.getLogger('').addHandler(console)


# Function to insert a username, password, and key value into the local database when the user enters in a username
# and password values in their respected entry boxes and hits the 'Submit' button.
def insert_variable_into_table(username, password, key, result):
    success = True
    try:
        # Make a connection to the local db
        path = os.path.dirname(os.path.abspath(__file__))
        db_file = os.path.join(path, 'users.db')
        sqlite_connection = sqlite3.connect(db_file)
        cursor = sqlite_connection.cursor()
        logging.info("Connected to SQLite")

        # SQL Insert query
        sqlite_insert_with_param = """INSERT INTO users (Username, Password, Key, RESULT) VALUES (?, ?, ?, ?);"""
        data = (username, password, key, result)
        # Run the Insert query
        cursor.execute(sqlite_insert_with_param, data)
        sqlite_connection.commit()
        logging.info("Python Variables inserted successfully into SqliteDb_developers table")
        cursor.close()
        return success
    except sqlite3.Error as error:
        success = False
        logging.error("Failed to insert Python variable into sqlite table", error)
        mb.showerror('Failed', 'Failed to insert Python variable into sqlite table')
        return success
    finally:
        if (sqlite_connection):  # Close the local db connection
            sqlite_connection.close()
            logging.info("The SQLite connection is closed")


# Function to check if the Username field is blank
def user_pass_check_empty():
    success = True
    if UE.get() and PE.get():
        success = True
        return success
    elif not UE.get() and PE.get():
        logging.error("Failed: Input is required for Username")
        mb.showerror('Failed', 'Input is required for Username')
        success = False
        return success
    elif not PE.get() and UE.get():
        logging.error("Failed: Input is required for Password")
        mb.showerror('Failed', 'Input is required for Password')
        success = False
        return success
    else:
        success = False
        logging.error("Failed: Input is required for Username and Password")
        mb.showerror('Failed', 'Input is required for Username and Password')
        return success


'''
Function that does the following:
- Generates a byte key
- Gets the username and password info from the user
- Encrypts the password data 
- Run the insert_variable_into_table function to put the username, password, key info in the local database
- Writes variables needed to encrypt/decrypt the data to a file
- Clears out the username and password entry boxes
- Pop up occurs letting the user know the username and password successfully saved
'''


def set_data_to_db():
    try:
        # Generate the key
        key = get_random_bytes(32)
        success_check = user_pass_check_empty()
        if not success_check:
            success = False
            success2 = False
        else:
            user = UE.get()
            user = user.casefold()
            pw = PE.get()

            # === Encrypt ===
            # First make your data a bytes object. To convert a string to a bytes object, we can call .encode() on it
            pw_data = pw.encode('utf-8')

            # Create the cipher object and encrypt the data
            cipher_encrypt = AES.new(key, AES.MODE_CFB)
            ct_bytes = cipher_encrypt.encrypt(pw_data)
            iv = b64encode(cipher_encrypt.iv).decode('utf-8')
            ct = b64encode(ct_bytes).decode('utf-8')
            result = json.dumps({'iv': iv, 'ciphertext': ct})
            print(result)
            # This is now our data
            ciphered_data = ct_bytes
            insert_variable_into_table(user, ciphered_data, key, result)
            # TO DO: Validation if the insert_variable_into_table hit an error or not
            success = True
            success2 = True

        # Clears out the username and password entry boxes
        UE.delete(0, tk.END)
        PE.delete(0, tk.END)

        # Successful pop up message
        if success and success2:
            mb.showinfo('Success', 'Data Successfully Saved')
    except Exception as e:
        logging.error("Something went wrong!", e)
        mb.showerror('Failed', 'Something went wrong!')


######################################################################################################################
# GUI Layout
######################################################################################################################


win = tk.Tk()
win.geometry('300x250')  # Set window size
win.resizable(0, 0)  # Fix window
bullet = "\u2022"  # 'Bullet'/dot format

# Username Label and Entry Box
UL = tk.Label(win, text="Username: ")
UE = tk.Entry(win)

# Password Label and Entry Box
PL = tk.Label(win, text="Password: ")
PE = tk.Entry(win, show=bullet)  # Calling 'bullet' format to hide the password from being seen

# Submit and Exit buttons
SB = tk.Button(win, text="Submit", padx=10, command=set_data_to_db)
EB = tk.Button(win, text="Exit", padx=15, command=win.quit)  # Closes the program

# File Menu Bar
menu_bar = tk.Menu(win)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=win.quit)  # Closes the program
menu_bar.add_cascade(label="File", menu=file_menu)

# Win App Grid
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
# File Menu Bar
win.config(menu=menu_bar)
# Win App Main Loop
win.mainloop()
