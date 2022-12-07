import random
import socket
import string
import threading
import json
import os
import rsa

from cryptography.fernet import Fernet
from rsa.transform import bytes2int, int2bytes

role = ""
user = []
userkey = []
nusers = 0
key = ""
fernet = None
nickname = ""
server_name = ""
data = []

def enter_server():
    global nickname
    global server_name
    global data
    os.system('cls||clear')
    # Enter servers.json to print the names of the servers
    with open('servers.json') as f:
        data = json.load(f)
    print('Your servers: ', end = "")
    # Print the servers that are stored in the servers.json file
    for servers in data:
        print(servers, end = " ")
    # Ask user for the name of the server to join
    server_name = input("\nEnter the server name: ")
    while server_name not in data:
        print('\nWrong server name.')
        print('Your servers: ', end="")
        for servers in data:
            print(servers, end=" ")
        server_name = input("\nEnter the server name: ")
    global nickname
    global password
    nickname = input("Choose Your Nickname: ")
    if nickname == 'admin':
        password = input("Enter Password for Admin: ")

    # Store the ip and port number for connection
    ip = data[server_name]["ip"]
    port = data[server_name]["port"]
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Connect to a host
    client.connect((ip,port))
    global public_key
    global private_key
    public_key, private_key = rsa.newkeys(2048)

os.system('cls||clear')
enter_server()
stop_thread = False

def sendpaswords():
    global key
    i = 0
    for usr in user:
        encrypted = rsa.encrypt(key.encode(), userkey[i])
        msg = f'YOURKEY.{usr}.{str(bytes2int(encrypted))}'
        client.send(msg.encode())
        i = i + 1

def recieve():
    global nickname, server_name, data, fernet, user, stop_thread, nusers, key
    while True:
        if stop_thread:
            break
        message = client.recv(4096).decode()
        if message == 'NICK':
            client.send(nickname.encode())
            next_message = client.recv(4096).decode()
            if next_message == 'PASS':
                client.send(password.encode())
                nextnext = client.recv(4096).decode()
                if nextnext == 'REFUSE':
                    print("Connection is Refused !! Wrong Password")
                    client.close()
                    stop_thread = True
            # Clients those are banned can't reconnect
            elif next_message == 'REPEATED':
                print('Client name already exists, restart the client.')
                client.close()
                stop_thread = True
            elif next_message == 'BAN':
                print('Connection Refused due to Ban')
                client.close()
                stop_thread = True
            elif next_message == 'USER':
                print('\nConnected, waiting for admin to encrypt the connection.')
        elif message == 'GIVEMEKEY':
            msg = f'MYKEY.{nickname}.{public_key.save_pkcs1().decode()}'
            client.send(msg.encode())
        elif message.startswith('MYKEY'):
            user.append(message.split('.')[1])
            usrkey = rsa.key.PublicKey.load_pkcs1(message.split('.')[2].encode())
            userkey.append(usrkey)
            if len(user) == nusers - 1:
                print("hemos recibido la respuesta de todos")
                key = Fernet.generate_key().decode()
                fernet = Fernet(key.encode())
                sendpaswords()
        elif message.startswith('NUSERS'):
            nusers = int(message.split('.')[1])
            print("Hay " + str(nusers) + " connectados. Esperando sus respuestas")
            client.send(f'GIVEMEKEYS'.encode())
        elif message.startswith('YOURKEY'):
            key = rsa.decrypt(int2bytes(int(message.split(nickname+".")[1])), private_key)
            fernet = Fernet(key)
            token = fernet.encrypt(data[server_name]["phrase"].encode()).decode()
            msg = f'MYPHRASE.{nickname}.{token}'
            client.send(msg.encode())
        elif message.startswith('MYPHRASE'):
            user = message.split('.')[1]
            secret = message.split('.')[2]
            if fernet.decrypt(secret).decode() == data[server_name]["phrase"]:
                print("user " + user + " validado.")
            else:
                print("user " + user + "no validado.")
        else:
            print(message)


def write():
    while True:
        if stop_thread:
            break
        #Getting Messages
        message = f'{nickname}: {input("")}'
        if message[len(nickname)+2:].startswith('/'):
            if nickname == 'admin':
                if message[len(nickname)+2:].startswith('/kick'):
                    # 2 for : and whitespace and 6 for /KICK_
                    client.send(f'KICK {message[len(nickname)+2+6:]}'.encode())
                elif message[len(nickname)+2:].startswith('/key'):
                    # 2 for : and whitespace and 5 for /BAN
                    client.send(f'GIVEMENUSERS'.encode())
                elif message[len(nickname)+2:].startswith('/ban'):
                    # 2 for : and whitespace and 5 for /BAN
                    client.send(f'BAN {message[len(nickname)+2+5:]}'.encode())
            else:
                print("Commands can be executed by Admins only !!")
        else:
            client.send(message.encode())

recieve_thread = threading.Thread(target=recieve)
recieve_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()