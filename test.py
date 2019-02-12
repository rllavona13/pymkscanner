import json

auth_file = open('/home/rrivera/Documents/Python_Projects/pymkscanner/auth.json')
login = json.load(auth_file)
auth_file.close()

usernames = login['username1']
passwords = login['password1']
my_usernames = iter(usernames)
my_passwords = iter(passwords)


print(next(my_usernames))