from random import randint
import secrets
from secp256k1 import n as GROUP_ORDER, scalar_add_multi, point_add_multi, point_mul, G
from reference import secret_share_shard, vss_commit, vss_verify, simplpedpop_round1, simplpedpop_finalize, vss_sum_commitments

def vss_correctness():
    def rand_polynomial(t):
        return [randint(1, GROUP_ORDER - 1) for _ in range(1, t + 1)]
    for t in range(1, 3):
        for n in range(t, 2*t + 1):
            f = rand_polynomial(t)
            shares = secret_share_shard(f, n)
            assert(len(shares) == n)
            assert(all(vss_verify(i, shares[i], vss_commit(f)) for i in range(n)))

def simulate_simplpedpop(seeds, t, n, Eq):
    assert(len(seeds) == n)
    r1_states = []
    vss_commitments = []
    all_generated_shares = []
    for i in range(n):
        state, vss_commitment, generated_shares = simplpedpop_round1(seeds[i], t, n)
        r1_states += [state]
        vss_commitments += [vss_commitment]
        all_generated_shares += [generated_shares]
    vss_commitments_sum = vss_sum_commitments(vss_commitments, t) 
    shares = []
    shared_pubkeys = []
    all_signer_pubkeys = []
    for i in range(n):
        shares_sum = scalar_add_multi([all_generated_shares[j][i] for j in range(n)])
        share, shared_pubkey, signer_pubkeys = simplpedpop_finalize(r1_states[0], i, vss_commitments_sum, shares_sum, Eq)
        shares += [share]
        shared_pubkeys += [shared_pubkey]
        all_signer_pubkeys += [signer_pubkeys]
    return shares, shared_pubkeys, all_signer_pubkeys

def dkg_correctness(t, n, simulate_dkg):
    t = 2
    n = 3
    Eq = lambda x: True
    seeds = [secrets.token_bytes(32) for _ in range(n)]
    shares, shared_pubkeys, signer_pubkeys = simulate_dkg(seeds, t, n, Eq)
    # check that the shared pubkey is the same for all participants
    assert(len(set(shared_pubkeys)) == 1)
    for i in range(1, n):
        assert(signer_pubkeys[0] == signer_pubkeys[i])

    # TODO: check that interpolating the signer pubkeys gives the shared pubkey

    # check that the share corresponds to the signer_pubkey
    for i in range(n):
        assert(point_mul(G, shares[i]) == signer_pubkeys[0][i])

def simplpedpop_correctness():
    for t in range(1, 3):
        for n in range(t, 2*t + 1):
            dkg_correctness(t, n, simulate_simplpedpop)

vss_correctness()
simplpedpop_correctness()