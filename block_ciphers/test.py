import ciphers
import key_generation


def AES_GCM_Test():
    byte_lengths = [16, 32]
    aes_mode = "AES-GCM"
    plaintexts = ["This is a AES-128-GCM test", "This is a AES-256-GCM test"]

    for byte_length, data in zip(byte_lengths, plaintexts):
        aes_key = key_generation.aes_key_generation(byte_length, aes_mode)

        enc_data = ciphers.encrypt_message("public.pem", aes_key, aes_mode, data)

        plaintext = ciphers.decrypt_message("private.pem", enc_data)
        assert plaintext == data


def AES_CBC_Test():
    byte_lengths = [16, 24, 32]
    aes_mode = "AES-CBC"
    plaintexts = ["This is a AES-128-CBC test", "This is a AES-192-CBC test", "This is a AES-256-CBC test"]

    for byte_length, data in zip(byte_lengths, plaintexts):
        aes_key = key_generation.aes_key_generation(byte_length, aes_mode)

        enc_data = ciphers.encrypt_message("public.pem", aes_key, aes_mode, data)

        plaintext = ciphers.decrypt_message("private.pem", enc_data)
        assert plaintext == data



if __name__ == "__main__":
    message = key_generation.generate_rsa_keys()
    print(message)

    AES_GCM_Test()
    AES_CBC_Test()
