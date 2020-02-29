import os
import sqlite3
import tkinter as tk
import logging
from tkinter import messagebox as mb
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


# Logging configurations
logging.basicConfig(filename='activity.log', level=logging.INFO,
                    format='%(asctime)s : %(levelname)s : %(message)s')


# Function to insert a username, password, and key value into the local database when the user enters in a username
# and password values in their respected entry boxes and hits the 'Submit' button.
def insert_variable_into_table(username, password, key):
    try:
        # Make a connection to the local db
        sqlite_connection = sqlite3.connect(os.getenv('db'))
        cursor = sqlite_connection.cursor()
        logging.info("Connected to SQLite")
        # SQL Insert query
        sqlite_insert_with_param = os.getenv('insert_user')
        data = (username, password, key)
        # Run the Insert query
        cursor.execute(sqlite_insert_with_param, data)
        sqlite_connection.commit()
        logging.info("Python Variables inserted successfully into SqliteDb_developers table")
        cursor.close()
    except sqlite3.Error as error:
        logging.error("Failed to insert Python variable into sqlite table", error)
        mb.showerror('Failed', 'Failed to insert Python variable into sqlite table')
    finally:
        if (sqlite_connection):    # Close the local db connection
            sqlite_connection.close()
            logging.info("The SQLite connection is closed")

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
        # key_location = os.getenv('key_location')
        encrypt_location = os.getenv('encrypt_variables')
        # Generate the key
        key = get_random_bytes(32)

        user = UE.get()
        user = user.casefold()
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
        insert_variable_into_table(user, ciphered_data, key)

        # # Save the key to a file
        # file_out = open(key_location, "wb")  # wb = write bytes
        # file_out.write(key)
        # file_out.close()

        # Save variables to file
        file_out2 = open(encrypt_location, "wb")
        file_out2.write(iv)
        file_out2.close()

        # Clears out the username and password entry boxes
        UE.delete(0, tk.END)
        PE.delete(0, tk.END)

        # Successful pop up message
        success = True
        if success:
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
bullet = "\u2022" # 'Bullet'/dot format

# Username Label and Entry Box
UL = tk.Label(win, text="Username: ")
UE = tk.Entry(win)

# Password Label and Entry Box
PL = tk.Label(win, text="Password: ")
PE = tk.Entry(win, show=bullet) # Calling 'bullet' format to hide the password from being seen

# Submit and Exit buttons
SB = tk.Button(win, text="Submit", padx=10, command=set_data_to_db)
EB = tk.Button(win, text="Exit", padx=15, command=win.quit) # Closes the program

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