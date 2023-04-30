from socket import *
import sys
import time #for timeing out if there is a halt, useful for debugging
import random
import pickle
from encrypt_class import enc_object
from block_ciphers.ciphers import *
from block_ciphers.key_generation import *
from test import *

def send():
    time.sleep(0.1)
    serverName = 'localhost'

    serverPort = 50243

    serverSocket = socket()
    serverSocket.connect((serverName, serverPort))
    open = 1
    while open:
        #command from user
        test_input = input("Input An Encyrption Method and Test Data Size (KB)\n" + 
                        "Options\n" + 
                        "A) CHACHA20-POLY1305\n" + 
                        "B) AES-256-GCM\n" + 
                        "C) AES-128-GCM\n" + 
                        "D) AES-256-CBC\n" + 
                        "E) AES-192-CBC\n" + 
                        "F) AES-128-CBC\n"+
                        "Example: A 100\n")
        
        if test_input == "exit":
            open = 0
            break

        test_input = test_input.strip()

        method = test_input[0]
        size = test_input[1:].strip()
        size = int(size)

        #generate random string
        test_message = ''
        for i in range(size * 1000):
            test_message += chr(random.randint(33, 126))
        #print(test_message)
        print(sys.getsizeof(test_message))

        public_key = "/home/babooze/CSE467-FinalReport/private.pem"
        #encrypt message
        start_enc = time.time()

        if method.startswith("A"):
            key = aes_key_generation(32, "ChaCha20_Poly1305")
            mode =  "ChaCha20_Poly1305"
            enc_key, enc_mode = encrypt_symmetric_key_mode(public_key, key, mode)
            encrypted_message = encrypt_message( key, mode, test_message)

        elif method.startswith("B"):
            key = aes_key_generation(32, "AES-GCM")
            mode =  "AES-GCM"
            enc_key, enc_mode = encrypt_symmetric_key_mode(public_key, key, mode)
            encrypted_message = encrypt_message( key, mode, test_message)
        elif method.startswith("C"):
            key = aes_key_generation(16, "AES-GCM")
            mode =  "AES-GCM"
            enc_key, enc_mode = encrypt_symmetric_key_mode(public_key, key, mode)
            encrypted_message = encrypt_message( key, mode, test_message)
        elif method.startswith("D"):
            key = aes_key_generation(32, "AES-CBC")
            mode =  "AES-CBC"
            enc_key, enc_mode = encrypt_symmetric_key_mode(public_key, key, mode)
            encrypted_message = encrypt_message( key, mode, test_message)
        elif method.startswith("E"):
            key = aes_key_generation(24, "AES-CBC")
            mode =  "AES-CBC"
            enc_key, enc_mode = encrypt_symmetric_key_mode(public_key, key, mode)
            encrypted_message = encrypt_message( key, mode, test_message)
        elif method.startswith("F"):
            key = aes_key_generation(16, "AES-CBC")
            mode =  "AES-CBC"
            enc_key, enc_mode = encrypt_symmetric_key_mode(public_key, key, mode)
            encrypted_message = encrypt_message( key, mode, test_message)
        end_enc = time.time()
        
        enc_object = (encrypted_message, enc_key, enc_mode)

        pickled = pickle.dumps(enc_object)
        start_send = time.time()
        print("sending")
        #print(test_message)
        #print("encrypted message", encrypted_message)
        serverSocket.send(pickled)
        print("done sending")
        end_send = time.time()

        enc_time = end_enc - start_enc
        send_time = end_send - start_send
        print("\ntime to encrypt:", enc_time)
        print("time to send to server:", send_time)
        dec_time = serverSocket.recv(2048).decode()
        print("time to decrypt:", dec_time)
        total_time = enc_time + send_time + float(dec_time)
        print("total time:", total_time, "\n")
        #serverSocket.recv(2048)

    serverSocket.close
send()