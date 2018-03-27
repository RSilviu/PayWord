

class Commitment:
    def __init__(self,
                 vendor_id,
                 pw_cert,
                 chain_root,
                 current_date,
                 info):
        self.vendor_id = vendor_id
        self.pw_cert = pw_cert
        self.chain_root = chain_root    # chain roots = []
        self.current_date = current_date
        self.info = info

if __name__ == '__main__':
    pass