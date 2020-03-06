import logging
import os
import sqlite3
import sys
import pyperclip
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv

# Logging configurations
logging.basicConfig(filename='activity.log',
                    level=logging.DEBUG,
                    format='%(asctime)s : %(levelname)s : %(message)s')

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

load_dotenv()

# OR, the same with increased verbosity
load_dotenv(verbose=True)

# OR, explicitly providing path to '.env'
from pathlib import Path  # python3 only
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)


def select_all_passwords():
    encrypt_location = os.getenv('encrypt_variables')
    try:
        # Read file and convert Encrypt variables into function variables
        # file_in2 = open(encrypt_location, 'rb')
        # iv = file_in2.read(16)
        # file_in2.close() # close file

        # Connect to the local database
        sqlite_connection = sqlite3.connect(os.getenv('db'))
        cursor = sqlite_connection.cursor()
        cursor2 = sqlite_connection.cursor()
        cursor3 = sqlite_connection.cursor()
        logging.info("Connected to SQLite")

        # No tuple format for username and IV data
        cursor.row_factory = lambda cursor, row: row[0]
        cursor3.row_factory = lambda cursor, row: row[0]
        # Get usernames query
        sqlite_select_with_param = os.getenv('select_user')
        # Get encrypted passwords query
        sqlite_select_with_param2 = os.getenv('select_pw')
        # Get encrypted IV query
        sqlite_select_with_param3 = os.getenv('select_iv')
        # Run usernames query
        cursor.execute(sqlite_select_with_param)
        # Run passwords query
        cursor2.execute(sqlite_select_with_param2)
        # Run IV query
        cursor3.execute(sqlite_select_with_param3)
        sqlite_connection.commit()
        logging.info("Python Variables read successfully into SqliteDb_developers table")
        # Fetch the data from the called queries
        db_users = cursor.fetchall()
        db_pws = cursor2.fetchall()
        db_iv = cursor3.fetchall()

        # For all users called, add to a list
        fetched_users = []
        for users in db_users:
            fetched_users.append(users)

        # For all pws called, add pw, key tuple to a list
        fetched_pws = []
        for pws in db_pws:
            fetched_pws.append(pws)

        fetched_iv = []
        for ivs in db_iv:
            fetched_iv.append(ivs)
        # Close db connection
        cursor.close()
        cursor2.close()
        sqlite_connection.close()
        logging.info("The SQLite connection is closed")
        # === Decrypt ===
        decrypt_pw = []
        # For each tuple in the fetched_pws list, decrypt the pw based on the key
        for pw, key in fetched_pws:
            for ivs in fetched_iv:
                ivs = ivs[0]
                iv = b64decode(pw['iv'])
                # Create the cipher object and decrypt the data
                cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=iv)
                deciphered_bytes = cipher_decrypt.decrypt(pw)

                # Convert the bytes object back to the string
                decrypted_data = deciphered_bytes.decode('utf-8')
                decrypt_pw.append(decrypted_data)
        # For every username in the fetched_users and decrypt_pw lists, add to the dictionary of PASSWORDS. Usernames
        # are the keys, passwords are the values.
        PASSWORDS = {k:v for k,v in zip(fetched_users, decrypt_pw)}
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
