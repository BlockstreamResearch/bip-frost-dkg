# BIP-DKG (WIP)

This document is a work-in-progress Bitcoin Improvement Proposal for a DKG that can be used in FROST.

## Introduction

### Distributed Key Generation (DKG)

Before being able to create signatures, the FROST signers need to obtain a shared public key and individual key shares that allow to sign for the shared public key.
This can be achieved through a trusted dealer who generates the shared public key and verifiably shares the corresponding secret key with the FROST signers.
If the dealer is dishonest or compromised, or the secret key is not deleted correctly and compromised later, an adversary can forge signatures.

To avoid the single point of failure when trusting the dealer, the signers run an interactive distributed key generation (DKG) protocol.
If the DKG for threshold `t` succeeds from the point of view of a signer and outputs a shared public key, then FROST signatures are unforgeable, i.e., `t` signers are required to cooperate to produce a signature for the shared public key - regardless of how many other participants in the the DKG were dishonest.

To instantiate a DKG there are many possible schemes which differ by the guarantees they provide.
Since DKGs are difficult to implement correctly in practice, the aim of this document is to describe pragmatic DKGs that are *simple*, namely SimplPedPop and EncPedPop. TODO
However, the DKG can be swapped out for a different one provided it is proven to be secure when used in FROST.

For each signer, the DKG has three outputs: a secret share, the shared public key, and individual public keys for partial signature verification.
The secret share and shared public key are required by a signer to produce signatures and therefore, signers *must* ensure that they are not lost.
You can refer to the [Backup and Recover](#backup-and-recover) section for additional details.

Once the DKG concludes successfully, applications should consider creating a FROST signature with all signers for some test message in order to rule out basic errors in the setup.

### Design

- **Large Number of Applications**: This DKG supports a wide range of scenarios. It can handle situations from those where the signing devices are owned and connected by a single individual, to scenarios where multiple owners manage the devices from distinct locations. The DKG can support situations where backup information is required to be written down manually , as well as those with ample backup space. To support this flexiblity, the document proposes several methods to [ensure agreement](#ensuring-agreement), including a potentially novel (?) network-based certification protocol.
- **DKG outputs per-participant public keys**: When DKG used in FROST allowing partial signature verification.
- **Optional instantiation of secure channels for share transfer** (TODO: may not remain optional)
- **Support for backups**
- **No robustness**: Very rudimentary ability to identify misbehaving signers in some situations.
- **Little optimized for communication overhead or number of rounds**

### Preliminaries

#### Notation

All participants agree on an assignment of indices `0` to `n-1` to participants.

* The function `chan_send(i, m)` sends message `m` to participant `i` (does not block).
* The function `chan_receive(i)` returns a message received by participant `i` (blocks).
* The functions `secure_chan_send(i, m)` and `secure_chan_receive(i)` are the same as `chan_send(i, m)` and `chan_send(i, m)` except that the message is sent through a secure (authenticated and encrypted) channel.
* The function `individual_pk(sk) is identical to the BIP 327 `IndividualPubkey` function.
* The function `verify_sig(pk, m, sig)` is identical to the BIP 340 `Verify` function.
* The function `sign(sk, m)` is identical to the BIP 340 `Sign` function.

```python
def kdf(seed, ...):
    # TODO
```

#### Verifiable Secret Sharing (VSS)

TODO: the functions from the irtf spec are a bit clunky to use for us...

```python
# Copied from draft-irtf-cfrg-frost-15
def polynomial_evaluate(x, coeffs):
   value = Scalar(0)
   for coeff in reverse(coeffs):
     value *= x
     value += coeff
   return value

# Copied from draft-irtf-cfrg-frost-15
def secret_share_shard_irtf(s, coefficients, MAX_PARTICIPANTS):
     # Prepend the secret to the coefficients
     coefficients = [s] + coefficients

     # Evaluate the polynomial for each point x=1,...,n
     secret_key_shares = []
     for x_i in range(1, MAX_PARTICIPANTS + 1):
       y_i = polynomial_evaluate(Scalar(x_i), coefficients)
       secret_key_share_i = (x_i, y_i)
       secret_key_shares.append(secret_key_share_i)
     return secret_key_shares, coefficients

def secret_share_shard(coefficients, MAX_PARTICIPANTS):
    # strip coefficients, strip indices
    shares = secret_share_shard_irtf(s, coefficients, MAX_PARTICIPANTS)[0]
    return [pair[0] for pair in shares]

# Copied from draft-irtf-cfrg-frost-15
def vss_commit(coeffs):
     vss_commitment = []
     for coeff in coeffs:
       A_i = G.ScalarBaseMult(coeff)
       vss_commitment.append(A_i)
     return vss_commitment

def vss_sum_commitments(vss_commitments, t):
    # TODO: using "Lloyd's trick", this optimization should be mentioned somewhere
    n = len(vss_commitments)
    # TODO: may instead raise BadParticipant(i)
    assert(all(len(vss_commitment[0]) == t for vss_commitment in vss_commitments)
    # The returned array consists of 2*n + t - 1 elements
    # [vss_commitments[0][0][0], ..., vss_commitments[n-1][0][0],
    #  sum(vss_commitments[i][1]), ..., sum(vss_commitments[i][t-1]),
    #  vss_commitments[0][1], ..., vss_commitments[n-1][1]]
    return [vss_commitments[i][0][0] for i in range(n)] +
           [sum([vss_commitments[i][0][j] for i in range(n)]) for j in range(1, t)] +
           [vss_commitments[i][1] for i in range(n)]

# Copied from draft-irtf-cfrg-frost-15
def vss_verify_irtf(share_i, vss_commitment)
     (i, sk_i) = share_i
     S_i = G.ScalarBaseMult(sk_i)
     S_i' = G.Identity()
     for j in range(0, MIN_PARTICIPANTS):
       S_i' += G.ScalarMult(vss_commitment[j], pow(i, j))
     return S_i == S_i'

def vss_verify(my_idx, summed_vss_commitments, summed_shares):
    return vss_verify_irtf((my_idx, summed_shares), summed_vss_commitments)

# Copied from draft-irtf-cfrg-frost-15
def derive_group_info(MAX_PARTICIPANTS, MIN_PARTICIPANTS, vss_commitment)
  PK = vss_commitment[0]
  participant_public_keys = []
  for i in range(1, MAX_PARTICIPANTS+1):
    PK_i = G.Identity()
    for j in range(0, MIN_PARTICIPANTS):
      PK_i += G.ScalarMult(vss_commitment[j], pow(i, j))
    participant_public_keys.append(PK_i)
  return PK, participant_public_keys
```

### SimplPedPop

TODO For each DKG, add a function that implements an entire protocol run (for one party) by calling the existing functions. This will involve adding a network abstraction (i.e., "send()" and "receive()" functions). Once we have a network abstraction, we can cleanly "implement" (in pseudocode) Eq protocols as functions and call them from DKGs.

We specify the SimplPedPop scheme as described in
[Practical Schnorr Threshold Signatures Without the Algebraic Group Model, section 4](https://eprint.iacr.org/2023/899.pdf)
with the following minor modifications:

- Adding individual's signer public keys to the output of the DKG. This allows partial signature verification.
- Very rudimentary ability to identify misbehaving signers in some situations.
- The proof-of-knowledge in the setup does not commit to the prover's ID. This is slightly simpler because it doesn't require the setup algorithm to take the ID as input.

SimplPedPop requires SECURE point-to-point channels between the participants, i.e., channels that are ENCRYPTED and AUTHENTICATED.
The messages can be relayed through a coordinator who is responsible to pass the messages to the participants as long as the coordinator does not interfere with the secure channels between the participants.

Also, SimplePedPop requires an interactive protocol `Eq` as described in section [Ensuring Agreement](#ensuring-agreement).

While SimplPedPop is able to identify participants who are misbehaving in certain ways, it is easy for a participant to misbehave such that it will not be identified.

```python
def simplpedpop_setup(seed, t, n):
    """
    Start SimplPedPop by generating messages to send to the other participants.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param int n: number of participants
    :return: a VSS commitment and shares
    """
    coeffs = [kdf(seed, "coeffs", i) for i in range(t)]
    # vss_commitment[0] denotes the commitment to the constant term
    vss_commitment = vss_commit(coeffs)
    # sk is the constant term of f and the dlog of vss_commitment[0]
    sk = coeffs[0]
    assert(vss_commitment[0] == pubkey_gen(sk))
    sig = sign(sk, "")
    # FIXME make sig a separate thing
    vss_commitment = (vss_commitment, sig)
    shares = secret_share_shard(coeffs, n):
    state = (t, n)
    return state, vss_commitment, shares

def simplpedpop_finalize(state, my_idx, summed_vss_commitments, summed_shares, Eq, eta = ()):
    """
    Take the messages received from the participants and finalize the DKG

    :param int my_idx:
    :param List[bytes] summed_vss_commitments: summed VSS commitments from all participants
        (including myself, TODO: it's unnecessary that we verify our own vss_commitment)
    :param scalar summed_shares: summed shares from all participants (including this participant) mod n
    :param eta: Optional argument for extra data that goes into `Eq`
    :return: a final share, the shared pubkey, the individual participants' pubkeys
    """
    t, n = state
    assert(n == len(shares) and 2*n + t - 1 == len(summed_vss_commitments))
    for i in range(n):
        if not verify_sig(summed_vss_commitments[i], "", summed_vss_commitments[n + t-1 + i]):
            raise BadParticipant(i)
    eta += (summed_vss_commitments)
    summed_vss_commitments_coeffs = sum([summed_vss_commitments[i] for i in range(n)]) + summed_vss_commitments[n:n+t-1]
    if not vss_verify(my_idx, summed_vss_commitments_coeffs, summed_shares):
        return False
    if Eq(eta) != SUCCESS:
        return False
    shared_pubkey, signer_pubkeys = derive_group_info(n, t, summed_vss_commitments_coeffs)
    return summed_shares, shared_pubkey, signer_pubkeys

# TODO: what about coordinator?
# TODO: we don't actually need to send everything through encrypted channel and we could relay some parts through the coordinator. But we don't want people to use SimplePedPop anyway.
def simplpedpop(seed, t, n, my_idx, Eq):
  state, my_vss_commitment, my_generated_shares = simplpedpop_setup(seed, t, n)
  for i in range(n)
      secure_chan_send(i, my_vss_commitment + my_generated_shares[i])
  for i in range(n):
      vss_commitments[i], shares[i] = secure_chan_receive(i)
  summed_vss_commitments = vss_sum_commitments(vss_commitments, t)
  return simplpedpop_finalize(state, my_idx, summed_vss_commitments, sum(shares), Eq, eta = ()):
```

### EncPedPop

#### Encryption

```python
def ecdh(x, Y):
    # TODO include (enckeys, t) in the hash to make sure we don't reuse one-time pads for different shares
    return Hash(x*Y)

def encrypt(share, my_deckey, enckey):
    return share + ecdh(my_deckey, enckey)
```

#### EncPedPop

EncPedPop is identical to SimplPedPop except that it does not require secure channels between the participants.
The participants start by generating an ephemeral key pair as per [BIP 327's IndividualPubkey](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-generation-of-an-individual-signer) for encrypting the 32-byte key shares.

TODO: Specify an encryption scheme. Good candidates are ECIES and the `crypto_box` authenticated PKE from NaCl, which is just ECDH+AEAD (https://doc.libsodium.org/public-key_cryptography/authenticated_encryption). Depending on the scheme, we could reuse keys for signatures and encryption but then we need stronger hardness assumptions (https://crypto.stackexchange.com/questions/37896/using-a-single-ed25519-key-for-encryption-and-signature). Performance per participant when using ECIES: 2 `ecmult_gen` (keygen, noncegen) + 2*(n-1) `ecmult_const` (ecdh for sending and receiving). When using `crypto_box`: 1x `ecmult_gen` (keygen), n-1 `ecmult_const` (ecdh, sending and receiving uses the same shared secret).

```python
def encpedpop_round1(seed):
    my_deckey = kdf(seed, "deckey")
    my_enckey = individual_pk(my_deckey)
    state1 = (my_deckey, my_enckey)
    return state1, my_enckey
```

The (public) encryption keys are distributed among each other.
They are not sent through authenticated channels but their correct distribution is ensured through the `Eq` protocol.
The receiver of an encryption key from participant `i` stores the encryption key in an array `enckeys` at position `i`.

TODO: there needs to be a global order of participants
TODO: explain how to arrive at the global order, in particular, by sorting enckeys

```python
def encpedpop_round2(seed, state1, t, n, enckeys):
    assert(n == len(enckeys))
    if len(enckeys) != len(set(enckeys)):
        raise DuplicateEnckeys

    my_deckey, my_enckey = state1
    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    seed_ = Hash(seed, t, enckeys)
    simpl_state, vss_commitment, shares = simplpedpop_setup(seed_, t, n)
    # TODO The encrypt function should have a randomness argument (or a secret key in case of AE).
    enc_shares = [encrypt(shares[i], my_deckey, enckeys[i]) for i in range(len(enckeys))
    state2 = (my_deckey, my_enckey, simpl_state, enckeys)
    return state2, vss_commitment, enc_shares
```

For every other participant `i`, the participant sends `vss_commitment` and `enc_shares[i]` through the communication channel.

```python
def encpedpop_finalize(state2, summed_vss_commitments, summed_enc_shares, Eq):
    my_deckey, my_enckey, simpl_state, enckeys = state2
    n = len(enckeys)
    assert(len(enc_shares) == n)

    summed_shares = summed_enc_shares - sum([ecdh(my_deckey, enckeys[i]) for i in range(n)]
    # TODO: catch "ValueError: not in list" exception
    my_idx = enckeys.index(my_enckey)
    eta = enckeys
    simplpedpop_finalize(simpl_state, my_idx, summed_vss_commitments, summed_shares, Eq, eta):
```

Note that if the public keys are not distributed correctly or the messages have been tampered with, `Eq(eta)` will fail.

```python
def encpedpop(seed, t, n, Eq):
    state1, my_enckey = encpedpop_round1(seed):
    for i in range(n)
        chan_send(i, my_enckey)
    for i in range(n):
      enckeys[i] = chan_receive(i)
    state2, my_vss_commitment, my_generated_enc_shares = encpedpop_round2(seed, state1, t, n, enckeys):
    for i in range(n)
        chan_send(i, my_vss_commitment + my_generated_enc_shares[i])
    for i in range(n):
        vss_commitments[i], enc_shares[i] = chan_receive(i)
    summed_vss_commitments = vss_sum_commitments(vss_commitments, t)
    return encpedpop_finalize(state2, summed_vss_commitments, sum(enc_shares), Eq)
```

### RecPedPop

RecPedPop is a wrapper around EncPedPop.
Its advantage is that recovering a signer is securely possible from a single seed and the full transcript of the protocol.
Since the transcript is public, every signer (and the coordinator) can store it to help recover any other signer.

Generate long-term host keys.

```python
def recpedpop_hostpubkey(seed):
    my_hostsigkey = kdf(seed, "hostsigkey")
    my_hostverkey = individual_pk(hostsigkey)
    return (my_hostsigkey, my_hostverkey)
```

Send host pubkey to every other participant.
After receiving a host pubkey from every other participant, compute a setup identifier.
TODO: there needs to be a global order of participants

```python
def recpedpop_setup_id(hostverkeys, t, context_string):
    setup_id = Hash(hostverkeys, t, context_string)
    setup = (hostverkeys, t, setup_id)
    return setup, setup_id
```

Compare the setup identifier with every other participant out-of-band.
If some other participant presents a different setup identifier, abort.

```python
def recpedpop_round1(seed, setup):
    hostverkeys, t, setup_id = setup

    # Derive setup-dependent seed
    seed_ = kdf(seed, setup_id)

    enc_state1, my_enckey =  encpedpop_round1(seed_)
    state1 = (hostverkeys, t, setup_id, enc_state1)
    return state1, my_enckey
```

The enckey received from participant `hostverkeys[i]` is stored at `enckeys[i]`.

```python
def recpedpop_round2(seed, state1, enckeys):
    hostverkeys, t, setup_id, enc_state1 = state1

    enc_state2, vss_commitment, enc_shares = encpedpop_round2(seed_, enc_state1, t, n, enckeys)
    state2 = (hostverkeys, setup_id, enc_state2)
    return state2, vss_commitment, enc_shares
```

```python
def recpedpop_finalize(seed, my_hostsigkey, state2, summed_vss_commitments, all_summed_enc_shares):
    (hostverkeys, setup_id, enc_state2) = state2

    # TODO Not sure if we need to include setup_id as eta here. But it won't hurt.
    # Include the enc_shares in eta to ensure that participants agree on all
    # shares, which in turn ensures that they have the right transcript.
    # TODO This means all parties who hold the "transcript" in the end should
    # participate in Eq?
    eta = setup_id + all_summed_enc_shares
    # TODO: fix my_idx
    my_summed_enc_shares = all_summed_enc_shares[my_idx]
    return encpedpop_finalize(enc_state2, summed_vss_commitments, my_summed_enc_shares, make_certifying_Eq(my_hostsigkey, hostverkeys), eta)
```

```python
def recpedpop(seed, my_hostsigkey, setup):
    state1, my_enckey = recpedpop_round1(seed, setup)
    for i in range(n)
        chan_send(i, my_enckey)
    for i in range(n):
      enckeys[i] = chan_receive(i)
    state2, my_vss_commitment, my_generated_enc_shares =  recpedpop_round2(seed, state1, enckeys)
    for i in range(n)
        # Send encrypted shares to everyone
        chan_send(i, my_vss_commitment + my_generated_enc_shares)
    for i in range(n):
        vss_commitments[i], all_enc_shares[i] = chan_receive(i)
    all_summed_enc_shares = [sum([all_enc_shares[from_][to] for from_ in range(n)]) for to in range(n)]
    # TODO: transcript misses certifying_Eq transcript
    transcript = (setup, enckeys, summed_vss_commitments, all_summed_enc_shares)
    summed_vss_commitments = vss_sum_commitments(vss_commitments, t)
    return recpedpop_finalize(seed, my_hostsigkey, state2, summed_vss_commitments, all_summed_enc_shares), transcript
```

![recpedpop diagram](images/recpedpop-sequence.png)

### Ensuring Agreement
TODO: The term agreement is overloaded (used for formal property of Eq and for informal property of DKG). Maybe rename one to consistency? Check the broadcast literature first

A crucial prerequisite for security is that participants reach agreement over the results of the DKG.
Indeed, disagreement may lead to catastrophic failure.
For example, assume that all but one participant believe that DKG has failed and therefore delete their secret key material,
but one participant believes that the DKG has finished successfully and sends funds to the resulting threshold public key.
Then those funds will be lost irrevocably, because, assuming t > 1, the single remaining secret share is not sufficient to produce a signature.

DKG protocols in the cryptographic literature often abstract away from this problem
by assuming that all participants have access to some kind of ideal "reliable broadcast" mechanism, which guarantees that all participants receive the same protocol messages and thereby ensures agreement.
However, it can be hard or even theoretically impossible to realize a reliable broadcast mechanism depending on the specific scenario, e.g., the guarantees provided by the underlying network, and the minimum number of participants assumed to be honest.

The DKG protocols described above work with a similar but slightly weaker abstraction instead.
They assume that participants have access to an equality check mechanism "Eq", i.e.,
a mechanism that asserts that the input values provided to it by all participants are equal.

Eq has the following abstract interface:
Every participant can invoke Eq(x) with an input value x. When Eq returns for a calling participant, it will return SUCCESS or FAIL to the calling participant.
 - SUCCESS means that it is guaranteed that all honest participants agree on the value x (but it may be the case that not all of them have established this fact yet). This means that the DKG was successful and the resulting aggregate key can be used, and the generated secret keys need to be retained.
 - FAIL means that it is guaranteed that no honest participant will output SUCCESS. In that case, the generated secret keys can safely be deleted.

As long as Eq(x) has not returned for some participant, this participant does not know whether all honest participants agree on the value or whether some honest participants have output SUCCESS or will output SUCCESS.
In that case, the DKG was potentially successful.
Other honest participants may believe that it was successful and may assume that the resulting keys can be used.
As a result, even if Eq appears to be stuck, the caller must not assume (e.g., after some timeout) that Eq has failed, and, in particular, must not delete the DKG state.

More formally, Eq must fulfill the following properties:
 - Integrity: If some honest participant outputs SUCCESS, then for every pair of values x and x' input provided by two honest participants, we have x = x'.
 - Consistency: If some honest participant outputs SUCCESS, no other honest participant outputs FAIL.
 - Conditional Termination: If some honest participant outputs SUCCESS, then all other participants will (eventually) output SUCCESS.
<!-- The latter two properties together are equivalent to Agreement in the paper. -->

Optionally, the following property is desired but not always achievable:
 - (Full) Termination: All honest participants will (eventually) output SUCCESS or FAIL.

#### Examples
TODO: Expand these scenarios. Relate them to SUCCESS, FAIL.

Depending on the application scenario, Eq can be implemented by different protocols, some of which involve out-of-band communication:

##### Participants are in a single room
In a scenario where a single user employs multiple signing devices (e.g., hardware wallets) in the same room to establish a threshold setup, every device can simply display its value x (or a hash of x under a collision-resistant hash function) to the user. The user can manually verify the equality of the values by comparing the values shown on all displays, and confirm their equality by providing explicit confirmation to every device, e.g., by pressing a button on every device.

TODO add failure case, specify entire protocol

Similarly, if signing devices are controlled by different organizations in different geographic locations, agents of these organizations can meet in a single room and compare the values.

These "out-of-band" methods can achieve termination (assuming the involved humans proceed with their tasks eventually).

##### Certifying network-based protocol
TODO The hpk should be the id here... clean this up and write something about setup assumptions

In a network-based scenario, where long-term host keys are available, the equality check can be instantiated by the following protocol:

```python
def make_certifying_Eq(my_hostsigkey, hostverkeys):
    def certifying_Eq(x):
        for i in range(n)
            chan_send(i, SIG, sign(my_hostsigkey, x))
        cert = [None] * len(hostverkeys)
        sig = [None] * len(hostverkeys)
        while(True)
            # TODO: this chan_receive is different to the one used in the
            #       pedpops. Change or specify.
            i, ty, msg = chan_receive()
            if ty == SIGNATURE:
                is_valid = verify(hostverkeys[i], x, msg)
                if sig[i] is None and is_valid:
                    sig[i] = msg
                elif not is_valid:
                    # The signer `hpk` is either malicious or an honest signer
                    # whose input is not equal to `x`. This means that there is
                    # some malicious signer or that some messages have been
                    # tampered with on the wire. We must not abort, and we could
                    # still output SUCCESS when receiving a cert later, but we
                    # should indicate to the user (logs?) that something went
                    # wrong.)
                if sig.count(None) == 0:
                    cert = sig
                    for i in range(n):
                        chan.send(i, CERT, cert)
                    return SUCCESS
            if ty == CERT:
                sigs = parse_cert(msg)
                if sigs is not None and len(sigs) == len(hostverkys):
                    is_valid = [verify(hostverkeys[i], x, sig[i]) \
                                for i in range(hostverkeys)]
                    if all(is_valid)
                        for i in range(n):
                            chan.send(i, CERT, cert)
                        return SUCCESS
    return certifying_eq
```

In practice, the certificate can also be attached to signing requests instead of sending it to every participant after returning SUCCESS.
It may still be helpful to check with other participants out-of-band that they have all arrived at the SUCCESS state. (TODO explain)

Proof. (TODO for footnote?)
Integrity:
Unless a signature has been forged, if some honest participant with input `x` outputs SUCCESS,
then by construction, all other honest participants have sent a signature on `x` and thus received `x` as input.
Conditional Termination:
If some honest participant with input `x` returns SUCCESS,
then by construction, this participant sends a list `cert` of valid signatures on `x` to every other participant.
Consider any honest participant among these other participants.
Assuming a reliable network, this honest participant eventually receives `cert`,
and by integrity, has received `x` as input.
Thus, this honest participant will accept `cert` and return SUCCESS.

##### Consensus protocol
If the participants run a BFT-style consensus protocol (e.g., as part of a federated protocol), they can use consensus to check whether they agree on `x`.

TODO: Explain more here. This can also achieve termination but consensus is hard (e.g., honest majority, network assumptions...)

### Backup and Recover

Losing the secret share or the shared public key will render the signer incapable of producing signatures.
These values are the output of the DKG and therefore, cannot be derived from a seed - unlike secret keys in BIP 340 or BIP 327.
In many scenarios, it's highly recommended to securely back up the secret share or the shared public key.

If the DKG output is lost, it is possible to ask the other signers to assist in recovering the lost data.
In this case, the signer must be very careful to obtain the correct secret share and shared public key (TODO)!
1. If all other signers are cooperative and their seed is backed up (TODO: do we want to encourage that?), it's possible that the other signers can recreate the signer's lost secret share, .
   If the signer who lost the share also has a seed backup, they can re-run the DKG.
2. If threshold-many signers are cooperative, they can use the "Enrolment Repairable Threshold Scheme" described in [these slides](https://github.com/chelseakomlo/talks/blob/master/2019-combinatorial-schemes/A_Survey_and_Refinement_of_Repairable_Threshold_Schemes.pdf).
   This scheme requires no additional backup or storage space for the signers.

If a signer has the option of deriving a decryption key from some securely backed-up seed and the other signers agree with storing additional data, the signer can use the following alternative backup strategy:
The signer encrypts their secret share to themselves and distributes it to every other signer.
If the signer loses their secret share, it can be restored as long as at least one other signer cooperates and sends the encrypted backup.
