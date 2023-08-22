# Pseudocode for various DKGs in python-like pseudocode

def helper_setup(seed, t, n):
    # vss_commit are the commitments to the coefficients (where vss_commit[0]
    # denotes the commitment to the constant term).
    # sk is the dlog of vss_commit[0]
    # gend_shares[i] is f(i+1) for signers {0, ..., n-1}
    vss_commit, sk, gend_shares = share(seed, t, n)
    assert(vss_commit[0] == pubkey_gen(sk))
    sig = sign(sk, i)
    return vss_commit, gend_shares, sig

# computes pk of a single signer
def helper_compute_pk(vss_commits, t, i):
    acc = 0
    for vss_commit in vss_commits:
        for t_ in range(t):
            acc += vss_commit[t]*((i+1)**k % n)
    return acc

def helper_dkg_output(shares, vss_commits, t):
    return sum(shares), sum([vss_commits[i][0] for i in range(n)]), [helper_compute_pk(vss_commits, t, i) for i in range(n)]

# SimplPedPop
#
# As described in the Olaf paper (with the addition of computing the individual's public keys)
def simplpedpop(secure_chan, seed, t, n):
    vss_commit, gend_shares, sig = helper_setup(seed, t, n)
    for i in n:
        secure_chan.send(i, sig  + vss_commit + gend_shares[i])
    nu = ()
    for i in n:
        sig, vss_commits[i], shares[i] = secure_chan.receive(i)
        if not verify_vss(vss_commits[i], shares[i]) or not verify_sig(sig, vss_commits[i][0], i)
        return False
        nu += (sig, vss_commit[i])
    if not Eq(nu):
        return False
    return helper_dkg_output(shares, vss_commits, t)

# SecPedPop
#
# Send over an insecure channel and ensure authenticity via Eq
def secpedpop(insecure_chan, seed, t, n):
    vss_commit, gend_shares, sig = helper_setup(seed, t, n)
    for i in n:
        insecure_chan.send(i, sig + vss_commit)
    nu = ()
    for i in n:
        sig, vss_commits[i] = insecure_chan.receive(i)
        nu += (sig, vss_commits[i])
        if not not verify_sig(sig, vss_commits[i][0], i)
        return False
    for i in n:
        insecure_chan.send(i, encrypt(gend_shares[i], vss_commits[i][0]))
    for i in n:
        shares[i] = decrypt(insecure_chan.receive(i), seed)
        if not verify_vss(vss_commits[i], shares[i])
        return False
    if not Eq(nu):
        return False
    return helper_dkg_output(shares, vss_commits, t)

# JessePedPop
#
# Purported advantages:
# - "It's more flexible because with the proposed API the VSS can be generated
#   prior to knowing the public keys of any participants"
# - uses public key instead of index
def jessepedpop(secure_chan, seed, t, n):
    # The pok is a signature of the empty message for the constant term of the
    # vss_commitment.
    pok, vss_commit = vss_gen(seed, t)
    for i in n:
        secure_chan.send(i, pok + vss_commit)
    for i in n:
        pok, vss_commits[i] = secure_chan.receive(i)
        # runs verify_sig(pok, vss_commits[i][0], "") internally
        # TODO: where does recipient pk come from? Maybe it's used instead of an index?
        gend_share = share_gen(pok, vss_commits[i], pk[i], t)
        if gend_share is None:
            return False
        secure_chan.send(i, gend_share)
    for i in n:
        shares[i] = secure_chan.receive(i)
    # runs verify_vss(vss_commits[i], shares[i]) for all i internally
    res = agg_shares(shares, vss_commits, t, n)
    if res is None:
        # If agg_shares fails, we can verify the individual shares to find
        # dishonest signers
        for i in n:
            share_verify(share[i], vss_commitments)
        return False
    agg_share, agg_pk, vss_hash = res
    # in contrast to SimplPedPop, vss_hash does _not_ contain the poks
    if not Eq(vss_hash):
        return False
    # use pubkey instead of index to compute_pk
    return agg_share, agg_pk, [helper_compute_pk(vss_commits, t, pk[i]) for i in range(n)]
    # jesse also signs and verifies vss_commitments, but I think that's unnecessary

