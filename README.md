# More Secure Password Locker
Inspired by the 'Automate the Boring Stuff with Python' project (https://automatetheboringstuff.com/chapter6/), which the user creates an unsecure password locker.
Instead of reading a dictionary in a file that shows usernames and passwords, I created a small GUI app that the user can enter a username/password combination.
The combination is sent to a local SQLite database with the password being encypted.

Windows users can the run the Windows Run Command, type `pw` and the username in which they want the password for.
This will start the process of calling the local database, decrypt the password and copy it for the user.
