# CSE467-FinalReport
This repository contains the files used for the experiment used in the CSE 467 Final Project Report.

## Ciphers
The following naive implementations of these symmetric ciphers are included:
* AES-CBC
* AES-GCM
* CHACHA20-POLY1305

The following naive implementations of these asymmetric ciphers are included:
* RSA

All ciphers can be found in ```/block_ciphers/ciphers.py```

These implementations are not intended to be used in practice and are closely related to the examples found in the PyCryptodome Python library. They are intended to be used to get a basic idea of their performance and analyze any security flaws present in them.

## Testing
The ciphers are ran across a basic peer to peer network using TCP. The symmetric encryption method chosen has its key encrypted using RSA and sent to the receiver, where it is decrypted. The ciphertext along with the nonce, and tag(if available) are generated and sent over to the receiver, where they can decrypt the ciphertext using the symmetric key they obtained and the nonce. If a tag was included the message can also be verified that it wasn't tampered with.

## Running
* Generate public and private keys by running ```generate_rsa_keys()``` found in  ```/ciphers/key_generation.py``` file.
  * The files will be located in the directory you ran the code in unless you specify the file location in the function.
* You will want to modify the location of your private and public keys in ```TCPclient.py``` and ```TCPserver.py``` respectively.
* ```TCPserver.py``` must be running in the background before ```TCPclient.py``` can be ran.
* Once both are running you will be able to specify the symmetric encryption method you wish to use and the amount of kilobytes of data you wish to send.
* The data will then be encrypted, sent to the server, and decrypted.
