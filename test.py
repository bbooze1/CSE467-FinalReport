from block_ciphers.ciphers import *
from block_ciphers.key_generation import *
from encrypt_class import enc_object


def AES_GCM_Test():
    byte_lengths = [16, 32]
    aes_mode = "AES-GCM"
    plaintexts = ["This is a AES-128-GCM test", "This is a AES-256-GCM test"]

    for byte_length, data in zip(byte_lengths, plaintexts):
        aes_key = key_generation.aes_key_generation(byte_length, aes_mode)

        enc_data = ciphers.encrypt_message("public.pem", aes_key, aes_mode, data)

        plaintext = ciphers.decrypt_message("private.pem", enc_data)
        assert plaintext == data


# def AES_CBC_Test():
#     byte_lengths = [16, 24, 32]
#     aes_mode = b"AES-CBC"
#     plaintexts = ["This is a AES-128-CBC test", "This is a AES-192-CBC test", "This is a AES-256-CBC test"]

#     for byte_length, data in zip(byte_lengths, plaintexts):
#         # generate a new symmetric key for the session and send it to the receiver using the public key
#         aes_key = key_generation.aes_key_generation(byte_length, aes_mode)
#         enc_aes_key_mode = ciphers.encrypt_symmetric_key_mode('public.pem', aes_key, aes_mode)

#         # the receiver will then decrypt it using their private key and use the symmetric key for the rest of the session
#         aes_key, aes_mode = ciphers.decrypt_symmetric_key_mode('private.pem', enc_aes_key_mode)

#         # run multiple times to simulate 100 messages being sent in the same session
#         for _ in range(100):
#             # sender will encrypt the message using the symmetric key and specific the encryption algorithm
#             enc_data = ciphers.encrypt_message(aes_key, aes_mode, data)

#             # receiver will decrypt the message using the symmetric key and specified encryption algorithm
#             plaintext = ciphers.decrypt_message(enc_data, aes_key, aes_mode)
#         assert plaintext == data



if __name__ == "__main__":
    # every time a new session is started first generate a new asymmetric key pair
    # The public key should be shared with the sender while the private key stays with the receiver
    message = generate_rsa_keys()
    print(message)
    AES_GCM_Test()
    # AES_CBC_Test()
