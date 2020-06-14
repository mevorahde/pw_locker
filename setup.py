import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need fine tuning.
build_exe_options = {"packages":["tkinter", "logging", "json", "sqlite3", "sys", "pyperclip", "Crypto.Cipher",
                                             "base64", "os"], "include_files":["favicon.ico", "users.db", "pw.bat"]}

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(  name = "Password_Locker",
        version = "1.0",
        description = "Add username/password credentials using a GUI into a local db. Password are encrypted into the "
                      "db and can be decrypted and copied for your use by using the Windows run command and typing "
                      "'pw' and then the username you'd like to get the password for. ",
        options = {"build_exe": build_exe_options},
        executables = [Executable("pw.py", base=base), Executable("pw_locker.pyw", base=base, icon="favicon.ico")])