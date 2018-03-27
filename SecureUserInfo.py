

class SecureUserInfo:
    def __init__(self,
                 aes_enc_info=None,
                 rsa_enc_aes_key=None):
        self.aes_enc_info = aes_enc_info
        self.rsa_enc_aes_key = rsa_enc_aes_key


