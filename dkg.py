# Pseudocode for various DKGs in python-like pseudocode

# TODO: DKG should also output aggpk and partial pk

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

# As described in the Olaf paper
def simplpedpop(secure_chan, seed, t, n):
    vss_commit, gend_shares, sig = helper_setup(seed, t, n)
    for i in n:
        secure_chan.send(i, sig  + vss_commit + gend_shares[i])
    nu = ()
    for i in n:
        sig, vss_commits[i], shares[i] = secure_chan.receive(i)
        if not verify(vss_commits[i], shares[i]) or not verify(sig, vss_commits[i][0], i)
        return False
        nu += (sig, vss_commit[i])
    if not Eq(nu):
        return False
    return helper_dkg_output(shares, vss_commits, t)

# Send over an insecure channel and ensure authenticity via Eq
def secpedpop(insecure_chan, seed, t, n):
    vss_commit, gend_shares, sig = helper_setup(seed, t, n)
    for i in n:
        insecure_chan.send(i, sig + vss_commit)
    nu = ()
    for i in n:
        sig, vss_commits[i] = insecure_chan.receive(i)
        nu += (sig, vss_commits[i])
        if not not verify(sig, vss_commits[i][0], i)
        return False
    for i in n:
        insecure_chan.send(i, encrypt(gend_shares[i], vss_commits[i][0]))
    for i in n:
        shares[i] = decrypt(insecure_chan.receive(i), seed)
        if not verify(vss_commits[i], shares[i])
        return False
    if not Eq(nu):
        return False
    return helper_dkg_output(shares, vss_commits, t)

# WIP: Current FROST module implementation
#
# Advantage: It's more flexible because with the proposed API the VSS can be generated prior to knowing the public keys of any participants
def jessepedpop(secure_chan, seed, t, n):
    # The pok is a pok for the "first coefficient" of the vss_commitment. The pok
    # is a signature of the empty message.
    # TODO: neat trick to save the pk, but why is that secure? It doesn't seem so.
    pok, vss_commit = vss_gen(seed, t)
    for i in n:
        secure_chan.send(i, pok + vss_commit)
    nu = ()
    for i in n:
        pok, vss_commits[i] = secure_chan.receive(i)
        # verifies pok and vss_commit
        # TODO: where does recipient_pk come from? Maybe it's used instead of an index?
        gend_share = share_gen(pok, vss_commits, recipient_pk, t)
        if gend_share is None:
        return False
        secure_chan.send(i, gend_share)
    for i in n:
        shares[i] = secure_chan.receive(i)
    # Verifies share against vss_commits
    res = agg_shares(shares, vss_commits, t, n)
    if res is None:
        return False
    agg_share, vss_hash = res
    for i in n:
        share_verify(share[i], vss)
