""" 
Enhanced Server Program for Secure Mail Transfer System

This module listens for incoming clients to the server
and prompts them with a menu that allows the client users
to access their inbox and send emails to other users.

authors: Mark Said, Nicholas Bao, Zoubere Yusuf
"""

import socket
import sys
import os, glob
from datetime import datetime
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

'''
This function activates the server program that listens 
for incoming client programs and communicates back and forth 
to allow the clients to access and manage the secure mail 
transfer system.

Parameters: 
None

Returns:
None
'''
def server():
    # Server port
    serverPort = 13000
    
    # Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    print('The server is ready to accept connections')
        
    # The server can have up to five connections in its queue waiting for acceptance
    serverSocket.listen(5)
        
    # Server accepting loop
    while 1:
        try:

            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            
            # Server forks and makes a child process to serve the client
            pid = os.fork()
            
            # If it is a client process
            if  pid == 0:
                
                # Close the server socket for the client process
                serverSocket.close() 

                # Server saves the server private key from the pem file
                file = open('server_private.pem', 'r')
                serverPriKey = RSA.import_key(file.read())
                file.close()

                # Server creates the decryption cypher using the server private key
                cipher_rsa_dec = PKCS1_OAEP.new(serverPriKey)
                
                # Server receives the client user info and decrypt using server private key
                encUserInfo = connectionSocket.recv(2048)
                userInfo = cipher_rsa_dec.decrypt(encUserInfo).decode('ascii')

                # Server saves the username and password
                userName, passWord = userInfo.split(' ')

                # Server reads the user info database, saves the data and closes the database file
                dataBase = open("user_pass.json", "r")
                data = json.load(dataBase)
                dataBase.close()

                # If the inputted username and password are in the database
                if userName in data:
                    if data[userName] == passWord:
                    
                        # Server saves the client public from the pem file
                        file = open(userName + "_public.pem")
                        clientPubKey = RSA.import_key(file.read())
                        file.close()

                        # Server Authentication
                        serverSignatureMessage = "This is the server digital signature message!"
                        print("Sent message: " + '"' + serverSignatureMessage + '"')
                        connectionSocket.send(serverSignatureMessage.encode('ascii'))

                        hash = SHA256.new(serverSignatureMessage.encode('ascii'))
                        print("The hash value of the message is:", hash.hexdigest())

                        while 1:
                            keyName = input("Enter the key filename for encryption (Private Key): ").strip()

                            try:
                                file = open(keyName, 'r')
                                key = RSA.import_key(file.read())
                                file.close()

                                try:
                                    serverSignature = pkcs1_15.new(key).sign(hash)
                                    connectionSocket.send(serverSignature)
                                
                                except:
                                    print("Must use a private key. Please try again.")
                                    continue

                                break
                            
                            except:
                                print("File not found. Please try again.")
                                continue

                        # Client Authentication
                        clientSignatureMessage = connectionSocket.recv(2048)

                        if clientSignatureMessage.decode('ascii') == "":
                            print("Client disconnected. Terminating connection.")
                            connectionSocket.close()
                            return

                        print("Received message: " + '"' + clientSignatureMessage.decode('ascii') + '"')

                        hash = SHA256.new(clientSignatureMessage)
                        print("The hash value of the message is:", hash.hexdigest())

                        clientSignature = connectionSocket.recv(2048)

                        while 1:
                            keyName = input("Enter the key filename for decryption: ").strip()

                            try:
                                file = open(keyName, 'r')
                                key = RSA.import_key(file.read())
                                file.close()

                                break
                            
                            except:
                                print("File not found. Please try again.")
                                continue

                        try:
                            pkcs1_15.new(key).verify(hash, clientSignature)
                            print("The signature of the " + userName + " is valid!")

                        except (ValueError, TypeError):
                            print("The signature of the " + userName + " is not valid! Terminating connection.")
                            connectionSocket.close()
                            return
                        
                        # Server generates SYM Key
                        KeyLen = 256
                        sym_key = get_random_bytes(int(KeyLen/8))

                        # Server generates an encryption cipher using the client public key
                        cipher_rsa_enc = PKCS1_OAEP.new(clientPubKey)

                        # Server prints message to the server user
                        print("Connection Accepted and Symmetric Key Generated for client: " + userName)

                        # Server encrypts the sym key using the encryption cipher
                        encSymKey = cipher_rsa_enc.encrypt(sym_key)        

                        # Server sends the encrypted sym key to the client
                        connectionSocket.send(encSymKey)

                    # Invalid password
                    else:

                        # Server creates message (Invalid Info), and sends it to the client
                        invalidInfo = "Invalid username or password"
                        connectionSocket.send(invalidInfo.encode('ascii'))

                        # Server prints message to the server user and terminates the connection
                        print("The received client information: " + userName + " is invalid (ConnectionTerminated).")
                        connectionSocket.close()
                        return

                # Invalid username
                else:
                    # Server creates message (Invalid Info), and sends it to the client
                    invalidInfo = "Invalid username or password"
                    connectionSocket.send(invalidInfo.encode('ascii'))

                    # Server prints message to the server user and terminates the connection
                    print("The received client information: " + userName + " is invalid (ConnectionTerminated).")
                    connectionSocket.close()
                    return
                
                # Server receives encrypted confirmation message using the sym key
                encConfirmMessage = connectionSocket.recv(2048)

                # Server generates a cipher block using the sym key
                cipher_sym = AES.new(sym_key, AES.MODE_ECB)

                # Server decrypts and unpads the confirmation message
                confirmMessage = unpad(cipher_sym.decrypt(encConfirmMessage), 16).decode('ascii')

                # Server creates the menu and sends it to the client
                menu = "Select the operation:\n"
                menu += "       1) Create and send an email\n"
                menu += "       2) Display the inbox list\n"
                menu += "       3) Display the email contents\n"
                menu += "       4) Termination the connection\n"
                menu += "\nChoice: "

                # Server pads and encrypts the menu
                encMenu = cipher_sym.encrypt(pad(menu.encode('ascii'), 16))

                # Server sends the encrypted menu to the client
                connectionSocket.send(encMenu)
		
		        # Initalizing empty lindex list for inbox
                inboxList = []

                # Get relative path to the current client's inbox
                inboxPath = os.path.dirname(os.path.abspath(__file__)) + "/" + userName
                inboxList = filter(lambda x: os.path.isfile(os.path.join(inboxPath, x)), os.listdir(inboxPath))
                 
                # Now sort the inbox based on creation time
                inboxList = sorted(inboxList, key = lambda x: os.path.getmtime(os.path.join(inboxPath, x)))
                inboxList.reverse() #reverse list since it is sorted by oldest to newest
                
                # Menu Loop
                while 1:

                    # Server receives encrypted choice from the client
                    encChoice = connectionSocket.recv(2048)

                    # Server decrypts the choice
                    choice = unpad(cipher_sym.decrypt(encChoice), 16).decode('ascii')

                    # If client chooses the sending email subprotocol
                    if choice == "1":
                        
                        # Begins email subprotocol by requesting email from client
                        emailMessage = "Send the email"
                        encEmailMessage = cipher_sym.encrypt(pad(emailMessage.encode('ascii'),16))
                        connectionSocket.send(encEmailMessage)

                        # Receives email size from client
                        encEmailSize = connectionSocket.recv(2048)
                        emailSize = int(unpad(cipher_sym.decrypt(encEmailSize), 16).decode('ascii'))
                        
                        # Server loop to receive email from client
                        bytestream = 0
                        encEmail = b''

                        while bytestream < emailSize:
                            encEmail += connectionSocket.recv(2048)
                            bytestream += len(encEmail)

                        # Decrypt fully received email
                        email = unpad(cipher_sym.decrypt(encEmail), 16).decode('ascii')
                        if email == "Invalid email":
                            print("Invalid email received from client. Content or title exceed maximum length")
                            continue

                        # Prints Server message
                        emailFormat = email.split("\n")
                        serverMessage = f"An email from {emailFormat[0].split(':')[1]} "
                        serverMessage += f"is sent to {emailFormat[1].split(':')[1]} "
                        serverMessage += f"has a content length of {emailFormat[3].split(':')[1]}."
                        print(serverMessage)

                        # Saves time of email reception and appends it to email
                        emailTime = str(datetime.now())
                        emailFormat.insert(2,emailTime)
                        email = "\n".join(emailFormat)

                        # Save email as a text file under appropriate directory
                        clientList = emailFormat[1].split(':')[1].split(";") # ex: To:client2;client3 -> [client2, client3]

                        for client in clientList:
                            filename = client + "_" + emailFormat[3].split(':')[1]
                            
                            # Uses relative path to save file from Server directory to Client directory
                            relativePath = f"./{client}/{filename}"
                            absPath = os.path.abspath(relativePath)

                            try:
                                with open(absPath, 'w') as f:
                                    f.write(email)

                            except: 
                                print("File failed to be written")
                        continue


                    # If client chooses the viewing inbox subprotocol
                    elif choice == "2":
                        
                        # Update the inbox for any new emails
                        inboxPath = os.path.dirname(os.path.abspath(__file__)) + "/" + userName
                        inboxList = filter(lambda x: os.path.isfile(os.path.join(inboxPath, x)), os.listdir(inboxPath))
                        
                        # Now sort the inbox based on creation time
                        inboxList = sorted(inboxList, key = lambda x: os.path.getmtime(os.path.join(inboxPath, x)))
                        inboxList.reverse() #reverse list since it is sorted by oldest to newest

                        # FOR LOOP that iterates through the inbox and formats the index list
                        sendIndex = "Index\tFrom\t\tDateTime\t\t\tTitle\n"
                        
                        for file_name in inboxList:
                            
                            # Get the path of the files
                            file_path = os.path.join(inboxPath, file_name)
                            
                            # Split file name into sender and title
                            sender = file_name.split("_")
                                                    
                            # Get the file's creation time
                            c_time = os.path.getctime(file_path)
                            
                            # Create the timestamp and index in the list
                            timestamp_str = str(datetime.fromtimestamp(c_time))
                            index = str(inboxList.index(file_name) + 1) + ".     "
                            
                            # Create each line of the interface for each email in the inbox
                            line = index + "\t" + sender[0] + "\t\t" + timestamp_str + "\t" + file_name.split("_")[1].removesuffix(".txt") + "\n"
                            sendIndex = sendIndex + line
                        
                        # Outside the for loop, send the encrpyted index and receive and OK from client                  
                        encIndex = cipher_sym.encrypt(pad(sendIndex.encode('ascii'), 16))
                        connectionSocket.send(encIndex)
                        OK = connectionSocket.recv(2048)
                        continue                


                    # If client chooses the viewing email subprotocol
                    elif choice == "3":
                        message = "the server request email index"
                        encMessage = cipher_sym.encrypt(pad(message.encode('ascii'), 16))
                        connectionSocket.send(encMessage)
                        
                        encDecide = connectionSocket.recv(2048)
                        decide = unpad(cipher_sym.decrypt(encDecide), 16).decode('ascii')
                       
                        if decide.isdigit():
                            
                            # Shift index by 1 since list starts at 0
                            index = int(decide) - 1
                        
                            # Check if client's choice is in inbox / inbox list has been generated
                            if index in range(len(inboxList)):
                                encYes = cipher_sym.encrypt(pad("YES".encode('ascii'), 16))
                                connectionSocket.send(encYes)
                                ok = connectionSocket.recv(2048)
                            
                                # Retrieve the directory of the client and the designated file
                                inbox_path = os.path.dirname(os.path.abspath(__file__)) + "/" +userName
                                file_path = os.path.join(inbox_path, inboxList[index])

                                # Get the contents of the email
                                with open(file_path, 'rb') as f:
                                    file_data  = f.read()
                                    
                                f.close()
                                
                                # Encrypt the file data and send it to the client
                                encEmail = cipher_sym.encrypt(pad(file_data, 16))

                                connectionSocket.sendall(encEmail)
                                connectionSocket.send(b"<END>")
                                        
                            else:
                                encNo = cipher_sym.encrypt(pad("NO".encode('ascii'), 16))
                                connectionSocket.send(encNo)
                                ok = connectionSocket.recv(2048)
                       	 
                        else:
                            encNo = cipher_sym.encrypt(pad("NO".encode('ascii'), 16))
                            connectionSocket.send(encNo)
                            ok = connectionSocket.recv(2048)
                       
                        continue

                    # If client chooses to terminate the connection
                    else:
                        print("Terminating connection with " + userName + ".")
                        connectionSocket.close()
                        return

            
            # Parent doesn't need this connection
            connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        
#-------
server()
