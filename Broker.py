from base64 import b64decode

from Crypto.PublicKey import RSA
from flask import Flask, request, jsonify

from AesCipher import AesCipher
from Commitment import Commitment
from Message import Message
from MessageUtil import to_b64_str, json2obj, to_json, b64_str_to_bytes, create_validation_msg
from Participant import Participant
from PWsettings import *

from Crypto.Hash import SHA256

from PayWordCert import PayWordCert
from datetime import datetime as dt
import time

from Payment import Payment
from Redemption import Redemption
from SecureUserInfo import SecureUserInfo
from UserInfo import UserInfo


class Broker(Participant):
    def __init__(self, identity):
        self.identity = identity
        self.pubKey = RSA.importKey(open(BROKER_PUBKEY_FILE).read()).exportKey()
        self.privKey = RSA.importKey(open(BROKER_PRIVKEY_FILE).read()).exportKey()
        self.users = {} #

    def inspect_user_info(self, user_info):
        # user info parsing
        user_info = json2obj(SecureUserInfo, user_info)
        aes_key = b64_str_to_bytes(user_info.rsa_enc_aes_key)
        privk = RSA.importKey(self.privKey)
        aes_key = privk.decrypt(aes_key)
        user_info = AesCipher(aes_key).decrypt(user_info.aes_enc_info)

        # actual tracking
        uid = SHA256.new(user_info.encode()).hexdigest()
        if uid in self.users:
            print('User already registered!')
        else:
            self.users[uid] = user_info
        return uid

    def create_cert(self, uid):
        msg = json2obj(Message, self.users[uid])
        user_info = json2obj(UserInfo, to_json(msg.m))
        if self.verify(to_json(user_info), msg.sig, b64_str_to_bytes(user_info.RSA_pubk)):
            data = PayWordCert(self.identity,
                               user_info.identity,
                               request.remote_addr,
                               to_b64_str(self.pubKey),
                               user_info.RSA_pubk,
                               time.time()+86400, # one day
                               'otherInfo')
            signature = self.sign(to_json(data))
            return Message(data, signature)
        else:
            return None

    def validate_redemption(self, redemption_json):
        redemption = json2obj(Redemption, redemption_json)
        commit_msg = json2obj(Message, to_json(redemption.commit_msg))
        last_payment = json2obj(Payment, to_json(redemption.last_payment))
        last_payment.pw = b64_str_to_bytes(last_payment.pw)

        commit = json2obj(Commitment, to_json(commit_msg.m))
        commit_sig = commit_msg.sig

        msg_cert = json2obj(Message, to_json(commit.pw_cert))
        pw_cert = json2obj(PayWordCert, to_json(msg_cert.m))
        # check exp date
        if float(pw_cert.exp) < float(commit.current_date):
            return create_validation_msg('Certificate has expired!',False)
        # verify user sig
        if not self.verify(to_json(commit), commit_sig, b64_str_to_bytes(pw_cert.user_pubk)):
            return create_validation_msg('Commit signature not authentic !!', False)
        # verify payment
        chain_root = b64_str_to_bytes(commit.chain_root)
        current_pw = last_payment.pw
        for _ in range(last_payment.index):
            current_pw = SHA256.new(current_pw).digest()
        if current_pw != chain_root:  # reject payword
            return create_validation_msg('Invalid payword !!', False)
        # valid redemption
        return str(last_payment.index*PW_VALUE), True



app = Flask(__name__)
broker = Broker('Paypal')


@app.route('/')
def send_pubkey():
    return to_b64_str(broker.pubKey)

@app.route('/register', methods=['POST'])
def on_register():
    user_info = request.get_json(force=True, silent=True)
    uid = broker.inspect_user_info(user_info)
    cert = broker.create_cert(uid)
    status = 201 if cert is not None else 401
    return to_json(cert), status

@app.route('/redeem', methods=['POST'])
def on_redeem():
    redeem_json = request.get_json(force=True, silent=True)
    msg, is_valid = broker.validate_redemption(redeem_json)
    status = 201 if is_valid else 400
    return msg, status


app.run(port=BROKER_PORT)















