class enc_object():

    def __init__(
        self, 
        new_key: bytes, 
        new_mode: bytes, 
        new_data: bytes,
    ) -> None:
        """Class usable to combine encrypted key, mode, and data to send to server

        Args:
            new_key: encrypted aes_key
            new_mode: encrypted aes_mode
            new_data: encrypted data
        Returns:
            None
        """
        
        self.aes_key = new_key
        self.mode = new_mode
        self.data = new_data