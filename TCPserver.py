from socket import *
import sys
import time 

def receive():
    print("started")
    rec_soc = socket() # Create a socket object
    host = "localhost" # Get local machine name
    port = 40500                 # Reserve a port for your service.
    rec_soc.bind((host, port))        # Bind to the port
    rec_soc.listen(5)
    print("connected")
    c, addr = rec_soc.accept()
    while True:
        print("in true")
        
        print("waiting")

        buffer = c.recv(2048)
        print(sys.getsizeof(buffer))
        print("receiving")
        message = b""
        continue_loop = 1
        while buffer and continue_loop:
            print("in here")
            message += buffer
            
            if sys.getsizeof(buffer) == 2081:
                
                buffer = c.recv(2048)
            else:
                continue_loop = 0
            print("buffer", buffer)

        message = message.decode()
        method = message[0]
        print("done receiving", message)

        start_dec = time.time()

        if method.startswith("A"):
            x = 1
        elif method.startswith("B"):
            x = 1
        elif method.startswith("C"):
            x = 1
        elif method.startswith("D"):
            x = 1
        elif method.startswith("E"):
            x = 1
        elif method.startswith("F"):
            x = 1
        end_dec = time.time()
        dec_time = (str)(start_dec - end_dec)
        print(dec_time)
        c.send(dec_time.encode())

receive()