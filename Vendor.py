from Crypto.Hash import SHA256

from Commitment import Commitment
from Message import Message
from Participant import Participant
from flask import Flask, request
from PWsettings import *
from MessageUtil import json2obj, to_json, b64_str_to_bytes, create_validation_msg, to_b64_str

import requests

from PayWordCert import PayWordCert
from Payment import Payment
from Redemption import Redemption


class Vendor(Participant):
    def __init__(self, identity):
        self.identity = identity
        self.to_receive = TO_RECEIVE
        self.commit_messages = []     # simple list of Commitment objects
        self.commitments = {}   # dict of commit hash -> chain root, commit hash ids user
        self.last_payment = {}  # last payment per commit, commit hash -> payment dict
        self.credit = 0
        # self.chain_roots = []

    def verify_commitment(self, commit_msg_json):
        msg = json2obj(Message, commit_msg_json)
        commitment = json2obj(Commitment, to_json(msg.m))
        msg_cert = json2obj(Message, to_json(commitment.pw_cert))
        pw_cert = json2obj(PayWordCert, to_json(msg_cert.m))
        # check exp date
        if float(pw_cert.exp) < float(commitment.current_date):
            return create_validation_msg('Certificate has expired!',False)
        # verify user sig
        if self.verify(to_json(commitment), msg.sig, b64_str_to_bytes(pw_cert.user_pubk)):
            # verify broker sig
            if self.verify(to_json(pw_cert), msg_cert.sig, b64_str_to_bytes(pw_cert.broker_pubk)):
                # track commit
                self.commit_messages.append(msg)
                # self.commitments.append(commitment)
                commit_hash = SHA256.new(to_json(commitment).encode()).hexdigest()
                self.commitments[commit_hash] = b64_str_to_bytes(commitment.chain_root)
                # self.chain_roots.append(commitment.chain_root)
                return create_validation_msg('Commitment accepted',True)
        return create_validation_msg('Signatures not matching!',False)


    def validate_payment(self, payment_json, commit_id):
        payment = json2obj(Payment, payment_json)
        payment.pw = b64_str_to_bytes(payment.pw)
        chain_root = self.commitments.get(commit_id)
        if chain_root is None:  # invalid chain_root
            return create_validation_msg('No such chain root !!',False)
        lp_dict = self.last_payment
        lp = lp_dict.get(commit_id)
        if lp is None or payment.index > lp.index:  # first payword or higher index (and hash match)
            #  check hash
            current_pw = payment.pw
            for _ in range(payment.index):
                current_pw = SHA256.new(current_pw).digest()
            if current_pw != chain_root:    # reject payword
                return create_validation_msg('Payword not from chain !!', False)
            # accept and store payword
            lp_dict[commit_id] = payment
            return create_validation_msg('Payword '+str(payment.index)+' accepted !!', True)
        return create_validation_msg('Payword '+str(payment.index)+' already used !!', False)


    def redeem_paywords(self):
        commit_msg = self.commit_messages[-1]
        commit = json2obj(Commitment, to_json(commit_msg.m))
        commit_hash = SHA256.new(to_json(commit).encode()).hexdigest()
        last_payment = self.last_payment[commit_hash]
        last_payment.pw = to_b64_str(last_payment.pw)
        redeem_msg = Redemption(commit_msg, last_payment)
        r = requests.post(REDEEM_ROUTE, json=to_json(redeem_msg))
        if r.status_code is 201:
            print('Paywords redeemed')
            print('credit before:', self.credit)
            self.credit += int(r.text)
            print('credit now:', self.credit)
        else:
            print('Paywords could not be redeemed')
            print('Reason:', r.text)

    def get_last_payment(self, commit_id):
        return self.last_payment[commit_id]


app = Flask(__name__)
vendor = Vendor('Netflix')


@app.route('/commit', methods=['POST'])
def on_commit():
    commitment = request.get_json(force=True, silent=True)
    msg, commit_accepted = vendor.verify_commitment(commitment)
    status = 201 if commit_accepted else 400
    return msg, status


@app.route('/<commit_id>/pay', methods=['POST'])    # commit_id is hex str
def on_payment(commit_id):
    payment_json = request.get_json(force=True, silent=True)
    msg, valid_payment = vendor.validate_payment(payment_json, commit_id)
    if valid_payment:
        last_received = vendor.get_last_payment(commit_id).index * PW_VALUE
        remaining_payment = vendor.to_receive - last_received
        status = 200 if remaining_payment > 0 else 201
    else:
        status = 400
    if status is 201:
        vendor.redeem_paywords()
    return msg, status


app.run(port=VENDOR_PORT)




















