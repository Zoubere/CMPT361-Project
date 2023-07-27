import socket
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def client():
    # Server Information (Prompts the user)
    serverName = input("Enter the server host name or IP: ").strip()
    serverPort = 13000
    
    # Create client socket that uses IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    # Deals with invalid server name
    try:

        # Client attempts to connect to the server
        clientSocket.connect((serverName,serverPort))
    
    # If connection failed
    except socket.error as e:
        
        # Prints a message and resets the program
        print('Error in client socket connection. Please try again.')
        client()

    try:

        # Client inputs username
        userName = input("Enter your username: ").strip()

        # Client inputs password
        passWord = input("Enter your password: ").strip()

        # Client sets up the user info to send to the server
        userInfo = userName + ' ' + passWord

        # Client saves the server public key from the pem file
        file = open('server_public.pem', 'r')
        serverPubKey = RSA.import_key(file.read())
        file.close()

        # Client creates the cipher using the server public key
        cipher_rsa_enc = PKCS1_OAEP.new(serverPubKey)

        # Client encrypts and encodes the message 
        encUserInfo = cipher_rsa_enc.encrypt(userInfo.encode('ascii').strip())
        
        # Client sends the encrypted user info
        clientSocket.send(encUserInfo)

        # Client receives the encrypted sym key or invalid user info message from the server
        keyOrInvalid = clientSocket.recv(2048)
    
        # Tests to see if keyOrInvalid is encrypted or not
        try:

            # Tries to decode
            keyOrInvalid = keyOrInvalid.decode('ascii') 

        except:

            # If decoding failed, the message is encrypted and it moves on
            pass
        

        # If invalid user info
        if str(keyOrInvalid) == "Invalid username or password":
            
            # Client prints a message to the client user
            print(keyOrInvalid + ".\nTerminating.")

            # Client terminates the connection and exits the program
            clientSocket.close()
            sys.exit(1)

        # Valid user info
        else:

            # Client saves the client private key from the pem file
            file = open(userName + '_private.pem', 'r')
            clientPriKey = RSA.import_key(file.read())
            file.close()

            # Client creates a decryption cypher using the client private key
            cipher_rsa_dec = PKCS1_OAEP.new(clientPriKey)
            
            # Client decrypts the sym key using the decryption cipher and saves it
            sym_key = cipher_rsa_dec.decrypt(keyOrInvalid)

            # Client generates a cipher block using the sym key
            cipher_sym = AES.new(sym_key, AES.MODE_ECB)

            # Client creates confirmation message to send to the server using the sym key
            confirmMessage = "OK"

            # Client pads and encrypts the confirmation message
            encConfirmMessage = cipher_sym.encrypt(pad(confirmMessage.encode('ascii'), 16))

            # Client sends the encrypted confirmation message
            clientSocket.send(encConfirmMessage)

            # Client receives the encrypted menu from the server
            encMenu = clientSocket.recv(2048)

            # Client decrypts and unpads the menu and saves it
            menu = unpad(cipher_sym.decrypt(encMenu), 16).decode('ascii')

            # Menu Loop
            while 1:

                # Client opens the menu and makes a choice
                choice = input(menu).strip()

                # Client encrypts the inputted menu choice and sends it to the server
                encChoice = cipher_sym.encrypt(pad(choice.encode('ascii'), 16))
                clientSocket.send(encChoice)
                
                # If client chooses the sending email subprotocol
                if choice == '1':
                    #print("Sending email subprotocol") # TEMPORARY

                    # Client receives the encrypted email message request
                    encEmailMessage = clientSocket.recv(2048)
                    emailMessage = unpad(cipher_sym.decrypt(encEmailMessage), 16).decode('ascii')

                    # Client sends the email destination client's username(s) 
                    if emailMessage == "Send the email":
                        destination = input("Enter destinations (separated by ;): ")

                        # Client enters the title of the email message
                        title = input("Enter title: ")

                        # Client enters the content of the email through terminal or txt file
                        contentMessage = input("Would you like to load contents from a file?(Y/N) ").upper()
                        if contentMessage == "Y":
                            file = input("Enter filename: ")
                            if os.path.isfile(file):
                                with open(file, 'r') as f:
                                    content = f.read()
                            else:
                                print(f"The {file} file does not exist in the current directory")
                        else:
                            content = input("Enter message contents: ")

                        # Title and content length exceed maximum character check
                        contentLength = len(content)
                        titleLength = len(title)
                        if contentLength > 1000000 or titleLength > 100:
                            email = "Invalid email"
                            encEmail = cipher_sym.encrypt(pad(choice.encode('ascii'), 16))
                            clientSocket.send(encEmail)
                            if titleLength > 100:
                                print("Title exceeds maximum length of 100 charachters email could not be sent")
                            else:
                                print("Content exceeds maximum length of 1000000 charachters email could not be sent")
                            continue
                        # Formats the email 

                        email = f"From:{userName}\n"
                        email += f"To:{destination}\n"
                        email += f"Title:{title}\n"
                        email += f"Content Length:{contentLength}\n"
                        email += f"Content:\n{content}"

                        # Send formatted and encrypted email to server
                        encEmail = cipher_sym.encrypt(pad(email.encode('ascii'), 16))
                        clientSocket.send(encEmail)
                        print("The message is sent to the server.")

                    continue

                # If client chooses the viewing inbox subprotocol
                elif choice == '2':
                    print("Viewing inbox subprotocol") # TEMPORARY
                    #receive the index list, decrypt it, and print it to the client
                    encIndex = clientSocket.recv(2048)                  
           
                    index = unpad(cipher_sym.decrypt(encIndex), 16).decode('ascii')
                    print(index)
                    
                    #reply to server with OK
                    OK = cipher_sym.encrypt(pad("OK".encode('ascii'), 16))
                    clientSocket.send(OK)
                    continue

                # If client chooses the viewing email subprotocol
                elif choice == '3':
                    print("Viewing email subprotocol") # TEMPORARY
                    #receive encrypted message from server
                    encMessage = clientSocket.recv(2048)
                    message = unpad(cipher_sym.decrypt(encMessage), 16).decode('ascii')                    
                    
                    #receive client's choice of index to view
                    view = "Enter the email index you wish to view: "
                    decide = input(view).strip()
                    
                    encDecide = cipher_sym.encrypt(pad(decide.encode('ascii'), 16))
                    clientSocket.send(encDecide)

                    
                    #get server response
                    encResponse = clientSocket.recv(1024)
                    response = unpad(cipher_sym.decrypt(encResponse), 16).decode('ascii')
                    OK = cipher_sym.encrypt(pad("HERE".encode('ascii'), 16))
                    clientSocket.send(OK)
                    
                    #email index was found
                    #Retrieve file contents
                    if response == "YES":
                    
                     done = False
                     file_bytes = b""
                    
                     while not done:
                      data = clientSocket.recv(2048)
                      file_bytes += data

                      if file_bytes[-5:] == b"<END>":

                       done = True
                    
                     file_contents = unpad(cipher_sym.decrypt(file_bytes[:-5]), 16).decode('ascii')
                     print(file_contents)
                    
                    
                    
                    #email index was not found
                    
                    elif response == "NO":
                     print("Cannot find email with index " + decide + ". Please check the inbox")
                     
                     
                    continue

                # If client chooses to terminate the connection
                else:
                    print('The connection is terminated with the server.')

                    break

        
        # Client terminate connection with the server and exits the program
        clientSocket.close()
        sys.exit(1)
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()