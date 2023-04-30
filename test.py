from block_ciphers.ciphers import *
from block_ciphers.key_generation import *
from encrypt_class import enc_object


def AES_GCM_Test():
    byte_lengths = [32]
    aes_mode = "ChaCha20_Poly1305".encode()
    plaintexts = ["T"]


    for byte_length, data in zip(byte_lengths, plaintexts):
        # generate a new symmetric key for the session and send it to the receiver using the public key
        aes_key = aes_key_generation(byte_length, aes_mode)
        enc_aes_key, enc_aes_mode = encrypt_symmetric_key_mode('public.pem', aes_key, aes_mode)

        # the receiver will then decrypt it using their private key and use the symmetric key for the rest of the session
        aes_key, new_aes_mode = decrypt_symmetric_key_mode('private.pem', enc_aes_key, enc_aes_mode)

        # run multiple times to simulate 100 messages being sent in the same session
        for _ in range(100):
            # sender will encrypt the message using the symmetric key and specific the encryption algorithm
            enc_data = encrypt_message(aes_key, new_aes_mode, data)
            enc = enc_object(enc_aes_key, enc_aes_mode, enc_data)

            # receiver will decrypt the message using the symmetric key and specified encryption algorithm
            plaintext = decrypt_message(enc_data, aes_key, new_aes_mode)
        assert plaintext == data


if __name__ == "__main__":
    # every time a new session is started first generate a new asymmetric key pair
    # The public key should be shared with the sender while the private key stays with the receiver
    message = generate_rsa_keys()
    print(message)
    AES_GCM_Test()
