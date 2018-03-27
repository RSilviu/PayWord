from Crypto.PublicKey import RSA
from Crypto import Random


####		RSA Key Gen - pub + priv
def generateRsaKeys(directory,size=1024):
    random_generator = Random.new().read
    key = RSA.generate(size, random_generator)
    private, public = key, key.publickey()
    open(directory+'/privkey.pem', 'wb').write(private.exportKey())
    open(directory+'/pubkey.pem', 'wb').write(public.exportKey())


if __name__ == '__main__':
    generateRsaKeys('broker-keys')
    generateRsaKeys('user-keys')