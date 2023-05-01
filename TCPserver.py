from socket import *
import sys
import time 
from encrypt_class import enc_object
from block_ciphers.ciphers import *
from block_ciphers.key_generation import *
from test import *

import pickle
def receive():
    """Server that receive and decrypts the message sent from the client.
        It must be started before the client can start.

    Args:
        None
    Returns:
        None
    """

    print("started")
    rec_soc = socket() # Create a socket object
    host = "localhost" # Get local machine name

    port = 50243             # Reserve a port for your service.

    rec_soc.bind((host, port))        # Bind to the port
    rec_soc.listen(5)
    print("connected")
    c, addr = rec_soc.accept()
    while True:
        private_key = "/home/babooze/CSE467-FinalReport/private.pem"
        print("in true")
        
        print("waiting")

        buffer = c.recv(2048)
        print(sys.getsizeof(buffer))
        print("receiving")
        message = b""
        continue_loop = 1
        while buffer and continue_loop:
            #print("in here")
            message += buffer
            
            #2081
            print(sys.getsizeof(buffer))
            if sys.getsizeof(buffer) == 2081:
                
                buffer = c.recv(2048)
            else:
                continue_loop = 0
            #print("buffer", buffer)

        #message = message.decode()
        #method = message[0]
        #print("done receiving", message)
        unpickled = pickle.loads(message)
        #print(unpickled)
        start_dec = time.time()
        aes_key, aes_mode = decrypt_symmetric_key_mode(private_key, unpickled[1], unpickled[2])
        decrypted_message = decrypt_message(unpickled[0], aes_key, aes_mode)
        end_dec = time.time()
        dec_time = (str)(end_dec - start_dec)
        print(dec_time)
        c.send(dec_time.encode())

receive()