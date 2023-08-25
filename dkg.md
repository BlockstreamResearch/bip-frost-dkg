## Distributed Key Generation

<!-- FROST requires a DKG -->
<!-- While there are many ways to instantiate a DKG this BIP specifies a simple DKG in a modular fashion. -->

<!-- TODO: We should mention that before sending funds to an address the signers should've created a signature. -->

<!-- - Do we want to support some sort of share backup scheme (see also [repairable threshold sigs](https://github.com/chelseakomlo/talks/blob/master/2019-combinatorial-schemes/A_Survey_and_Refinement_of_Repairable_Threshold_Schemes.pdf))that sends share encrypted-to-self to other signers? As long as one other signer cooperates we can restore. -->

We describe two DKG protocols: SimplPedPop and SecPedPop.

### SimplPedPop

We specify the SimplPedPop scheme as described in [Practical Schnorr Threshold Signatures
Without the Algebraic Group Model, section 4](https://eprint.iacr.org/2023/899.pdf) with the following minor modifications:

- Using [arbitrary 33-byte arrays][https://github.com/frostsnap/frostsnap/issues/72] to identify signers instead of indices. Note that for correctness they need to be unique, but not for unforgeability. Indices are not ideal because they imply a global order of the participants.
- Adding individual's signer public keys to the output of the DKG. This allows partial signature verification.
- Very rudimentary ability to identify misbehaving signers in some situations.

SimplPedPop requires SECURE channels between the participants, i.e., ENCRYPTED and AUTHENTICATED.
Also we require an interactive protocol `Eq` as described in section [Broadcast](TODO).
Note that with some instantiations of `Eq` SimplPedPop may fail but the signer still cannot delete any secret key material.

While SimplPedPop is able to identify participants who are misbehaving in certain ways, it is generally easy for a participant to misbehave such that it will not be identified.

```python
def simplpedpop_setup(seed, t, ids):
    """
    Start SimplPedPop by generating messages to send to the other participants.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param List[bytes] ids: 33-bytes that identify the participants, must be unique
    :return: a VSS commitment and shares
    """
    f = polynomial_gen(seed)
    # vss_commit[0] denotes the commitment to the constant term
    vss_commit = commit_coefs(f)
    # sk is the constant term of f and the dlog of vss_commit[0]
    sk = f[0]
    assert(vss_commit[0] == pubkey_gen(sk))
    # TODO: what should we sign? SimplPedPop signs identifier,
    # JessePedPop signs a tag. The latter is slightly simpler
    # because we don't need to know our own id.
    sig = sign(sk, "")
    vss_commit = vss_commit || sig
    shares = [ f(Hash_sometag(Id)) for Id in ids ]
    return vss_commit, shares
```

In SimplPedPop every participant has secure channels to every other participant.
For every other participant `id[i]`, the participant sends `vss_commit` and `shares[i]` through the secure channel.

```python
def simplpedpop_finalize(ids, my_id, vss_commits, shares, eta = ()):
    """
    Take the messages received from the participants and finalize the DKG

    :param List[bytes] ids: 33-bytes that identify the participants, must be unique
    :param my_id bytes: 33-bytes that identify this participant, must be in ids
    :param List[bytes] vss_commits: VSS commitments from all participants
        (including myself, TODO: it's unnecessary that we verify our own vss_commit)
    :param List[bytes] shares: shares from all participants (including myself)
    :param eta: Optional argument for extra data that goes into `Eq`
    :return: a final share, the pubkey, the individual participant's pubkeys
    """
    for i in n:
        if not verify_vss(my_id, vss_commits[i], shares[i]):
            throw BadParticipant(ids[i])
        if not verify_sig(vss_commits[i].sig, vss_commits[i][0], "")
            throw BadParticipant(ids[i])
    eta += (sig, vss_commit[i])
    if not Eq(eta):
        return False
    # helper_compute_pk computes the individual pubkey of participant with the given id
    signer_pubkeys = [helper_compute_pk(vss_commits, t, ids[i]) for i in range(n)]
    pubkey = sum([vss_commits[i][0] for i in range(n)])
    return sum(shares), pubkey, signer_pubkeys
```

### SecPedPop

SecPedPop is identical to SimplPedPop except that it does not require secure channels between the participants.
Before running `secpedpop_setup` the participants generate a public key as per [IndividualPubkey](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-generation-of-an-individual-signer) and distribute it among each other.

Note that if the public keys are not distributed correctly or the messages have been tampered with, `Eq(eta)` will fail.
However, if `Eq(eta)` does fail, then confidentiality of the share may be broken, which makes it even more important to not reuse seeds.

```python
def secpedpop_setup(seed, t, pubkeys):
    # TODO: optional strengthening of the seed, could also be part of SimplPedPop
    seed = Hash(seed, t, pubkeys)
    vss_commit, shares = simplpedpop_setup(seed, t, pubkeys)
    enc_shares = [encrypt(shares[i], pubkeys[i]) for i in range(len(pubkeys))
    return vss_commit, enc_shares
```

For every other participant `id[i]`, the participant sends `vss_commit` and `enc_shares` through the communication channel.

```python
def secpedpop_finalize(pubkeys, my_pubkey, vss_commit, enc_shares):
  shares = [decrypt(enc_share, sec) for enc_share in enc_shares]
  eta = pubkeys
  return simplpedpop_finalize(pubkeys, my_pubkey, vss_commit, shares, eta):
```
