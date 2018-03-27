import json
from base64 import b64encode, b64decode
from collections import namedtuple

from PayWordCert import PayWordCert


def to_json(obj):
    return json.dumps(obj, default=lambda m: m.__dict__,
                      indent=4)

def _json_object_hook(d): return namedtuple('X', d.keys())(*d.values())

# def json2obj(data): return json.loads(data, object_hook=_json_object_hook)

def json2obj(cls,data): return cls(**(json.loads(data)))

def to_b64_str(data):
    return b64encode(data).decode()

def b64_str_to_bytes(data):
    return b64decode(data.encode())


# info message constants

ok_pref = '[OK]'
error_pref = '[ERROR]'

def create_validation_msg(msg, is_valid):
    pref = ok_pref if is_valid else error_pref
    return pref+' '+msg, is_valid


if __name__ == '__main__':
    x = b'hello'
    print('bytes x:', x)
    print('str x:', x.decode())
    # print(to_json(json2obj_simple(PayWordCert,x)))

    # d = {'a':{
    #     'b': 'c',
    #     'd':{
    #         'e': 3
    #     }
    # },
    # 'f': 4}
    # x = json.dumps(d, indent=4)
    # print(x)
    # print()
    # x = json.loads(x)
    # print(type(x))
    # print()










