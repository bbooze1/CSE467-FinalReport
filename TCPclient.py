from socket import *
import sys
import time #for timeing out if there is a halt, useful for debugging
import random
import pickle
from block_ciphers.ciphers import *
from block_ciphers.key_generation import *
from test import *

def send():
    time.sleep(0.1)
    serverName = 'localhost'
    serverPort = 40500
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

        public_key = "/home/braeden/School/CSE467-FinalReport/public.pem"
        #encrypt message
        start_enc = time.time()

        if method.startswith("A"):
            x = 1
        elif method.startswith("B"):
            x = 1
            key = aes_key_generation(32, "AES-GCM")
            encrypted_message = encrypt_message(key, "AES-GCM", test_message)
        elif method.startswith("C"):
            x = 1
            key = aes_key_generation(16, "AES-GCM")
            encrypted_message = encrypt_message(key, "AES-GCM", test_message)
        elif method.startswith("D"):
            x = 1
            key = aes_key_generation(32, "AES-CBC")
            encrypted_message = encrypt_message(key, "AES-CBC", test_message)
        elif method.startswith("E"):
            x = 1
            key = aes_key_generation(24, "AES-CBC")
            encrypted_message = encrypt_message(key, "AES-CBC", test_message)
        elif method.startswith("F"):
            x = 1
            key = aes_key_generation(16, "AES-CBC")
            encrypted_message = encrypt_message(key, "AES-CBC", test_message)
        end_enc = time.time()

        start_send = time.time()
        print("sending")
        print(test_message)
        print("encrypted message", encrypted_message)
        serverSocket.send(encrypted_message)
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