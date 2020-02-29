import os
import sqlite3
import sys
import pyperclip
import logging
from Crypto.Cipher import AES

logging.basicConfig(filename='activity.log', level=logging.INFO,
                    format='%(asctime)s : %(levelname)s : %(message)s')


def select_all_passwords():
    key_location = os.getenv('key_location')
    encrypt_location = os.getenv('encrypt_variables')
    try:
        with open(key_location, 'rb') as f:
            first_line = f.readline().rstrip()

        key = first_line
        file_in2 = open(encrypt_location, 'rb')
        iv = file_in2.read(16)
        file_in2.close()

        sqlite_connection = sqlite3.connect(os.getenv('db'))
        cursor = sqlite_connection.cursor()
        cursor2 = sqlite_connection.cursor()
        logging.info("Connected to SQLite")
        cursor.row_factory = lambda cursor, row: row[0]
        cursor2.row_factory = lambda cursor, row: row[0]
        sqlite_select_with_param = os.getenv('select_user')
        sqlite_select_with_param2 = os.getenv('select_pw')
        cursor.execute(sqlite_select_with_param)
        cursor2.execute(sqlite_select_with_param2)
        sqlite_connection.commit()
        logging.info("Python Variables read successfully into SqliteDb_developers table")
        db_users = cursor.fetchall()
        db_pws = cursor2.fetchall()

        fetched_users = []
        for users in db_users:
            fetched_users.append(users)

        fetched_pws = []
        for pws in db_pws:
            fetched_pws.append(pws)

        cursor.close()
        cursor2.close()
        sqlite_connection.close()
        logging.info("The SQLite connection is closed")
        # === Decrypt ===
        decrypt_pw = []
        for pw in fetched_pws:
            # Create the cipher object and decrypt the data
            cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
            deciphered_bytes = cipher_decrypt.decrypt(pw)

            # Convert the bytes object back to the string
            decrypted_data = deciphered_bytes.decode('utf-8')
            print("Decrypted data:", decrypted_data)
            decrypt_pw.append(decrypted_data)

        PASSWORDS = {k:v for k,v in zip(fetched_users, decrypt_pw)}
        return PASSWORDS
    except sqlite3.Error as error:
        logging.error("Failed to read Python variable into sqlite table", error)


PASSWORDS = []
PASSWORDS = select_all_passwords()

if len(sys.argv) < 2:
    print('Usage: python pow.py[account] - copy account password')
    sys.exit()

account = sys.argv[1]  # first command line arg is account name

account_case = account.casefold()


if account or account_case in PASSWORDS:
    pyperclip.copy(select_all_passwords(PASSWORDS[account]))
    print('Password for {} copied to clipboard.'.format(account))
else:
    print('There is no account named {}.'.format(account))