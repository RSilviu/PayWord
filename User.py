import time
import requests
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random

import AesUtil
from AesCipher import AesCipher
from Commitment import Commitment
from Message import Message
from MessageUtil import to_json, to_b64_str, b64_str_to_bytes, json2obj
from PWsettings import *
from Participant import Participant
from PayWordCert import PayWordCert
from Payment import Payment
from PwChain import PwChain
from SecureUserInfo import SecureUserInfo
from UserInfo import UserInfo


class User(Participant):
    def __init__(self, identity, credit):
        self.identity = identity
        self.credit = credit
        self.to_pay = TO_PAY
        self.brokerPubKey = None  # bytes
        self.pubKey = RSA.importKey(open(USER_PUBKEY_FILE).read()).exportKey() # bytes
        self.privKey = RSA.importKey(open(USER_PRIVKEY_FILE).read()).exportKey()
        self.cert = None
        # self.chains = {}
        self.chains = []
        self.chain_roots = []
        self.commitments = []

    def get_broker_pubkey(self):
        r = requests.get(BROKER_ADDR)
        if r.status_code is 200:
            self.brokerPubKey = b64_str_to_bytes(r.text)
        else:
            print('Could not get Broker PubKey!')

    def get_info(self):
        ubInfo = UserInfo(self.identity,
                          to_b64_str(self.pubKey),
                          '1234')
        signature = self.sign(to_json(ubInfo))

        msg = Message(ubInfo, signature)
        msg = to_json(msg)

        aes_key = AesUtil.derive_key()
        enc_user_info = AesCipher(aes_key).encrypt(msg)

        pubk = RSA.importKey(self.brokerPubKey)
        compat_param = 7
        enc_aes_key = pubk.encrypt(aes_key, compat_param)[0]
        enc_aes_key = to_b64_str(enc_aes_key)

        sui = SecureUserInfo(enc_user_info, enc_aes_key)
        return to_json(sui)

    def get_cert(self):
        info = self.get_info()
        msg = requests.post(CERT_ROUTE, json=info).text
        msg = json2obj(Message, msg)   # PayWordCert(**dict(json))
        if msg is None:
            print('No Payword cert received')
        else:
            cert = json2obj(PayWordCert, to_json(msg.m))
            if self.verify(to_json(cert), msg.sig, b64_str_to_bytes(cert.broker_pubk)):
                print('Cert is OK')
                self.cert = Message(cert, msg.sig)
            else:
                print('Cert is not safe')

    # dict of chains with optimum values from 1-sum
    # def generate_chains(self):
    #     n_val_pairs = [(1,2),(3,4)]     # dp function !!!!!!!!!!!!!!!!!!! of random of list(range(self.to_pay+1)), self.to_pay
    #     for pair in n_val_pairs:
    #         n, val = pair
    #         seed = Random.get_random_bytes(SHA256.digest_size)
    #         chain = PwChain(n, seed, val)
    #         chain_root = chain.get_root()
    #         self.chains[chain_root] = seed
    #         self.chain_roots.append(chain_root)

    def generate_chain(self, pw_val=PW_VALUE):  # fixed pw val
        seed = Random.get_random_bytes(SHA256.digest_size)
        # val = random.choice([1,2,5,10])
        n = TO_PAY // pw_val
        chain = PwChain(n,seed,pw_val)
        chain_root = chain.get_root()
        # self.chains[chain_root] = seed
        self.chains.append(chain)
        self.chain_roots.append(chain_root)



    def compute_commit(self, vendor_id):
        commit = Commitment(vendor_id,
                            self.cert,
                            to_b64_str(self.chain_roots[-1]),
                            # [to_b64_str(root) for root in self.chain_roots],
                            time.time(),
                            'other info')
        signature = self.sign(to_json(commit))
        msg = Message(commit, signature)
        # self.commitments.append(msg)
        self.commitments.append(commit)
        return msg

    def commit_to_vendor(self, vendor_id):
        commit = self.compute_commit(vendor_id)
        r = requests.post(COMMIT_ROUTE, json=to_json(commit))
        if r.status_code is 201:
            print('Commit accepted')
            return True
        else:
            print('Commit refused')
            return False


    def pay(self):
        pw_chain = self.chains[-1]
        commit_id = SHA256.new(to_json(self.commitments[-1]).encode()).hexdigest()
        pay_route = '/'.join([VENDOR_ADDR, commit_id, 'pay'])
        pw_index = random.randint(1,pw_chain.n) # to demo refused payments
        pw = to_b64_str(pw_chain.get_pw(pw_index))
        p = Payment(pw,pw_index)
        r = requests.post(pay_route, json=to_json(p))
        print()
        print(r.text)
        if r.status_code in (200, 201):
            total_paid = pw_index * pw_chain.pw_val
            if r.status_code is 200:
                print('Paid so far:', total_paid)
            else:
                print('Done paying')
                print('Total paid:', total_paid)
                print('Initial credit:', self.credit)
                self.credit -= total_paid
                self.to_pay = 0
                print('Remaining credit:', self.credit)


    def try_payment(self):
        print('To pay:', self.to_pay)
        while self.to_pay > 0:
            self.pay()
        print('Remaining payment:', self.to_pay)


if __name__ == '__main__':
    u = User('Silviu Rusu', 100)
    u.get_broker_pubkey()
    u.get_cert()
    u.generate_chain()
    commit_accepted = u.commit_to_vendor('Netflix')
    if commit_accepted:
        u.try_payment()
        # u.pay()

    # print(open(USER_PUBKEY_FILE).read())
    # m = 'hello'
    # s = u.sign(m)
    # u.verify(m, s, b64_str_to_bytes(to_b64_str(u.pubKey)))













