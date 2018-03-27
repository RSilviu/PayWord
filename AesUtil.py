
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES


__all__ = ['pad','unpad','derive_key']


def pad(s):
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + pad_len * chr(pad_len)


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def derive_key(password='secret',salt_len=16,key_len=16):
    salt = Random.get_random_bytes(salt_len)
    return PBKDF2(password,salt,key_len)
