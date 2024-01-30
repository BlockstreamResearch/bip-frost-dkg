from random import randint
from secp256k1 import n as GROUP_ORDER
from reference import secret_share_shard, vss_commit, vss_verify

def correctness():
    def rand_polynomial(t):
        return [randint(1, GROUP_ORDER - 1) for _ in range(1, t + 1)]
    for t in range(1, 3):
        for n in range(t, 2*t + 1):
            f = rand_polynomial(t)
            shares = secret_share_shard(f, n)
            assert(len(shares) == n)
            assert(all(vss_verify(i, shares[i], vss_commit(f)) for i in range(n)))

correctness()