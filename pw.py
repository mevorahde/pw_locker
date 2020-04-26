import logging
import json
import sqlite3
import sys
import pyperclip
from base64 import b64decode
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


def select_all_passwords():
    try:
        # Connect to the local database
        path = os.path.dirname(os.path.abspath(__file__))
        db_file = os.path.join(path, 'users.db')
        sqlite_connection = sqlite3.connect(db_file)
        cursor = sqlite_connection.cursor()
        logging.info("Connected to SQLite")

        # Get table query
        select_user = """SELECT Username, Password, Key, Result FROM users;"""
        sqlite_select_with_param = select_user
        # Run table query
        cursor.execute(sqlite_select_with_param)
        sqlite_connection.commit()
        logging.info("Python Variables read successfully into Sqlite DB table")
        # Fetch the data from the called queries
        db_users_all = cursor.fetchall()

        # For all users info called, add to a list
        fetched_users_all = []
        for users in db_users_all:
            fetched_users_all.append(users)
        cursor.close()
        sqlite_connection.close()
        logging.info("The SQLite connection is closed")

        # === Decrypt ===
        l_users = []
        decrypt_pw = []
        # For each tuple in the fetched_pws list, decrypt the pw based on the key
        for username, pw, key, results in fetched_users_all:
            l_users.append(username)
            b64 = json.loads(results)
            ct = b64decode(b64['ciphertext'])
            iv = b64decode(b64['iv'])
            # Create the cipher object and decrypt the data
            cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
            dec_pw = cipher_decrypt.decrypt(ct)
            dpw = dec_pw.decode('utf-8')
            decrypt_pw.append(dpw)
        # For every username in the l_users and decrypt_pw lists, add to the dictionary of PASSWORDS. Usernames
        # are the keys, passwords are the values.
        PASSWORDS = {k:v for k,v in zip(l_users, decrypt_pw)}
        return PASSWORDS
    except sqlite3.Error as error:
        logging.error("Failed to read Python variable into sqlite table", error)


# Set the variable PASSWORDS to the dictionary returned from the select_all_passwords function.
PASSWORDS = select_all_passwords()

# If the 'run' argument is less than 2 characters, explain the process to the user.
if len(sys.argv) < 2:
    print('Usage: python pw.py[account] - copy account password')
    sys.exit()

# Set the account variable to the second argument
account = sys.argv[1].lower()  # first command line arg is account name


try:
    # If the second argument is a key is the PASSWORDS dictionary, copy it's value, the decrypted password for the user.
    if account in PASSWORDS:
        pyperclip.copy(PASSWORDS[account])
        print('Password for {} copied to clipboard.'.format(account))
    else:
        print('There is no account named {}.'.format(account))
except Exception as e:
    logging.exception(e.args)
    print("Cannot process your request at this time.")
