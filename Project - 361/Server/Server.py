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
		
		#initalizing empty lindex list for inbox
                inboxList = []
                #Get relative path to the current client's inbox
                inboxPath = os.path.dirname(os.path.abspath(__file__)) + "/" + userName
                inboxList = filter(lambda x: os.path.isfile(os.path.join(inboxPath, x)), os.listdir(inboxPath))
                 
                #Now sort the inbox based on creation time
                inboxList = sorted(inboxList, key = lambda x: os.path.getmtime(os.path.join(inboxPath, x)))
                inboxList.reverse() #reverse list since it is sorted by oldest to newest
                
                # Menu Loop
                while 1:

                    # Server receives encrypted choice from the client
                    encChoice = connectionSocket.recv(2048)

                    # Server decrypts the choice
                    choice = unpad(cipher_sym.decrypt(encChoice), 16).decode('ascii')
                    print(choice)

                    # If client chooses the sending email subprotocol
                    if choice == "1":
                        print("Sending email subprotocol") # TEMPORARY

                        continue


                    # If client chooses the viewing inbox subprotocol
                    elif choice == "2":
                        print("Viewing inbox subprotocol") # TEMPORARY
                        #update the inbox for any new emails
                        inboxPath = os.path.dirname(os.path.abspath(__file__)) + "/" + userName
                        inboxList = filter(lambda x: os.path.isfile(os.path.join(inboxPath, x)), os.listdir(inboxPath))
                        #Now sort the inbox based on creation time
                        inboxList = sorted(inboxList, key = lambda x: os.path.getmtime(os.path.join(inboxPath, x)))
                        inboxList.reverse() #reverse list since it is sorted by oldest to newest

                        
                        #FOR LOOP that iterates through the inbox and formats the index list
                        sendIndex = "Index\tFrom\t\tDateTime\t\t\tTitle\n"
                        for file_name in inboxList:
                        #Get the path of the files
                         file_path = os.path.join(inboxPath, file_name)
                         #split file name into sender and title
                         sender = file_name.split("_")
                                                  
                         #get the file's creation time
                         c_time = os.path.getctime(file_path)
                         
                         #Create the timestamp and index in the list
                         timestamp_str = str(datetime.fromtimestamp(c_time))
                         index = str(inboxList.index(file_name) + 1) + ".     "
                         
                         # create each line of the interface for each email in the inbox
                         line = index + "\t" + sender[0] + "\t\t" + timestamp_str + "\t" + file_name.split("_")[1].removesuffix(".txt") + "\n"
                         sendIndex = sendIndex + line
                        
                        #Outside the for loop, send the encrpyted index and receive and OK from client   
                                           
                        encIndex = cipher_sym.encrypt(pad(sendIndex.encode('ascii'), 16))
                        connectionSocket.send(encIndex)
                        OK = connectionSocket.recv(2048)
                        continue                


                    # If client chooses the viewing email subprotocol
                    elif choice == "3":
                       print("Viewing email subprotocol") # TEMPORARY
                       message = "the server request email index"
                       encMessage = cipher_sym.encrypt(pad(message.encode('ascii'), 16))
                       connectionSocket.send(encMessage)
                       
                       encDecide = connectionSocket.recv(2048)
                       decide = unpad(cipher_sym.decrypt(encDecide), 16).decode('ascii')
                       
                       if decide.isdigit():
                        #shift index by 1 since list starts at 0
                        index = int(decide) - 1
                       
                        #check if client's choice is in inbox/ inbox list has been generated
                        if index in range(len(inboxList)):
                       	 encYes = cipher_sym.encrypt(pad("YES".encode('ascii'), 16))
                       	 connectionSocket.send(encYes)
                       	 ok = connectionSocket.recv(2048)
                       
                       	 #Retrieve the directory of the client and the designated file
                       	 inbox_path = os.path.dirname(os.path.abspath(__file__)) + "/" +userName
                       	 file_path = os.path.join(inbox_path, inboxList[index])

                       	 #Get the contents of the email
                       	 with open(file_path, 'rb') as f:
                       		 file_data  = f.read()
                       		
                       	 f.close()
                       	
                       	 #encrypt the file data and send it to the client
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
        # except:
        #     print('Goodbye')
        #     serverSocket.close() 
        #     sys.exit(0)
            
        
#-------
server()