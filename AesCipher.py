from base64 import b64encode, b64decode
from Crypto import Random
from Crypto.Cipher import AES
from MessageUtil import to_b64_str
import AesUtil

class AesCipher:
    """
    m
    c = AesCipher(key,[mode]).encrypt(m)
    m = AesCipher(key,[mode]).decrypt(c)
    """
    def __init__(self, key, mode=AES.MODE_CFB):
        self.key = key
        self.mode = mode

    def encrypt(self, m):
        m = AesUtil.pad(m)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, self.mode, iv)
        return to_b64_str(iv + cipher.encrypt(m))

    def decrypt(self, c):
        c = b64decode(c.encode())
        iv = c[:AES.block_size]
        cipher = AES.new(self.key, self.mode, iv)
        return AesUtil.unpad(cipher.decrypt(c[AES.block_size:])).decode()


if __name__ == '__main__':
    aes_key = AesUtil.derive_key()
    c = AesCipher(aes_key).encrypt('flash')
    print(AesCipher(aes_key).decrypt(c))
















