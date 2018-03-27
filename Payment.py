

class Payment:
    def __init__(self,pw,index):    #,chain_root=None):
        self.pw = pw
        self.index = index
        # self.chain_root = chain_root

# def get_pw_values(coins, value):
#     table = [None for x in range(value + 1)]
#     table[0] = []
#     for i in range(1, value + 1):
#         for coin in coins:
#             if coin > i: continue
#             elif not table[i] or len(table[i - coin]) + 1 < len(table[i]):
#                 if table[i - coin] is not None:
#                     table[i] = table[i - coin][:]
#                     table[i].append(coin)
#     return table[-1]

if __name__ == '__main__':
    coins = [3, 5, 12]
    # print(get_pw_values(coins, 25))