from Crypto import Random
from Crypto.Hash import SHA256


class PwChain:
    def __init__(self, n, seed, pw_val):
        self.n = n
        self.pw_val = pw_val
        self.chain = self.__generate(n, seed)
        # self.currentPos = 0
        # self.is_active = True
        # self.is_used

    def __generate(self, n, seed):
        chain = [seed]
        for _ in range(n):
            pw = SHA256.new(chain[-1]).digest()
            chain.append(pw)
        return list(reversed(chain))

    # def is_usable(self):
    #     return self.currentPos < self.n + 1

    def get_pw(self, index):
        return self.chain[index]
        # self.currentPos += index
        # return self.chain[self.currentPos] if self.is_usable() else None

    def get_seed(self):        # cn
        return self.chain[-1]

    def get_root(self):
        return self.chain[0]


if __name__ == '__main__':
    seed = Random.get_random_bytes(SHA256.digest_size)
    chain = PwChain(10, seed, 5)


#   cn  cn-1    cn-2    cn-3 ... c0
#    0   1       2                n













