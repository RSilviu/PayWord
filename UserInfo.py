from Message import Message


class UserInfo:
    def __init__(self, identity='user',RSA_pubk=None,card_no='7xx-34x'):
        self.identity = identity
        self.RSA_pubk = RSA_pubk
        self.card_no = card_no

if __name__ == '__main__':
    from MessageUtil import to_json, json2obj

    msg = Message()
    msg.m = UserInfo()
    msg.sig = 'my sig = sr'

    j = to_json(msg)
    print(j)
    print()
    obj = json2obj(j)
    print(obj.m.card_no)








