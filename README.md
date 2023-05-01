# CSE467-FinalReport
This repository contains the files used for the experiment used in the CSE 467 Final Project Report.

## Ciphers
The following naive implementations of these symmetric ciphers are included:
* AES-CBC
* AES-GCM
* CHACHA20-POLY1305

The following naive implementations of these asymmetric ciphers are included:
* RSA

These implementations are not intended to be used in practice and are closely related to the examples found in the PyCryptodome Python library. They are intended to be used to get a basic idea of their performance and analyze any security flaws present in them.

# Testing
The ciphers are ran across a basic peer to peer network using TCP. The symmetric encryption method chosen has its key encrypted using RSA and sent to the receiver, where it is decrypted. The ciphertext along with the nonce, and tag(if available) are generated and sent over to the receiver, where they can decrypt the ciphertext using the symmetric key they obtained and the nonce. If a tag was included the message can also be verified that it wasn't tampered with.

# Documentation
Link
