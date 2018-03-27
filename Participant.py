from base64 import b64encode, b64decode

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

from MessageUtil import to_b64_str, b64_str_to_bytes


class Participant:
    def __init__(self):
        self.privKey = None
        self.pubKey = None

    """
    in: m - JSON str
    out: base64 - str
    """

    def sign(self, m):
        m = m.encode()
        h = SHA256.new(m)
        signer = PKCS1_PSS.new(RSA.importKey(self.privKey))  # key is bytes
        signature = signer.sign(h)
        return to_b64_str(signature)

    """
    in: m - JSON, sig - base64 str, pubk-str
    """

    def verify(self, m, signature, pub_key):
        m = m.encode()
        signature = b64_str_to_bytes(signature)
        h = SHA256.new(m)
        verifier = PKCS1_PSS.new(RSA.importKey(pub_key))    # string or bytes?
        if verifier.verify(h, signature):
            # print('The signature is authentic.')
            return True
        else:
            # print('The signature is not authentic.')
            return False








