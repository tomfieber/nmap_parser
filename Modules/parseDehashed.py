#!/usr/bin/env python3

import json
import sys


class ParseDehashed(object):
    def __init__(self, file, options):
        self.file = file
        self.options = options

    def parse_dehashed_json(self, dict, password_spray, credential_stuffing):
        with open(self.file, "r") as json_file:
            try:
                data = json.load(json_file)
            except json.decoder.JSONDecodeError:
                print("Something went wrong. Check your json file and try again.")
                sys.exit()

            entries = data['entries']
            for user in entries:
                email = user['email'].split(';')[0].strip()
                password = user['password']
                password_hash = user['hashed_password']
                database_name = user['database_name']
                username = user['username']
                creds = {'password': {password}, 'username': {username},
                         'hash': {password_hash}, 'database': {database_name}}

                usr = email.split('@')[0].strip()
                if usr not in password_spray:
                    password_spray.append(usr)

                if password != '' or password_hash != '':
                    if email not in dict.keys():
                        dict[email] = creds
                    else:
                        dict[email]['username'].add(username)
                        dict[email]['password'].add(password)
                        dict[email]['hash'].add(password_hash)
                        dict[email]['database'].add(database_name)
                    if password != '':
                        stuff = usr, password
                        if stuff not in credential_stuffing:
                            credential_stuffing.append(stuff)