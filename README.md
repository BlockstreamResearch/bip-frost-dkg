# Distributed Key Generation for FROST (BIP draft)

### Abstract

This document is a work-in-progress Bitcoin Improvement Proposal proposing Distributed Key Generation methods for use in FROST.

### Copyright

This document is licensed under the 3-clause BSD license.

## Introduction

### Motivation

In the FROST threshold signature scheme [KG20], a threshold `t` of some set of `n` signers is required to produce a signature.
FROST remains unforgeable as long as at most `t-1` signers are compromised,
and remains functional as long as `t` honest signers do not lose their secret key material.

As a result, threshold signatures increase both security and availability,
enabling users to escape the inherent dilemma between the contradicting goals of protecting a single secret key against theft and data loss simultaneously.
Before being able to create signatures, the FROST signers need to obtain a shared public key and individual key shares that allow to sign for the shared public key.
This can, in principle, be achieved through a trusted dealer who generates the shared public key and distributes shares of the corresponding secret key to the FROST signers.
However, the dealer is a single point of failure:
if the dealer is malicious or compromised, or the secret key is not deleted correctly and compromised later, an adversary can forge signatures.

An interactive *distributed key generation* (DKG) protocol run by all signers avoids the need for a trusted dealer.
There exist a number of DKG protocols with different requirements and guarantees.
Most suitably for the use with FROST is the PedPop DKG (``Pedersen DKG with proofs of possession'') [KG20, CKM21, CGRS23].
But similar to most DKG protocols in the literature, the PedPop DKG has strong requirements on the communication between signers:
It assumes that signers have secure (i.e., authenticated and encrypted) channels between each other to deliver secret shares to individual signers,
and it assumes that signers have access to a secure broadcast mechanism.

This requirements make PedPop difficult to implement correctly in practice, 
and the aim of this document is to describe simple variants of PedPop with "batteries included",
i.e., they incorporate minimal but sufficient implementations of secure channels and secure broadcast.

### Design

Our protocols are based on the SimplPedPop protocol, which has been proven to be secure when combined with FROST [CGRS23] and needs only a single invocation of an equality check protocol.
The equality check protocol is a particular abstraction of a broadcast mechanism with restricted functionality that ensures all signers have the same view of the DKG protocol, thereby roughly resembling a secure broadcast mechanism.
SimplPedPop does not have a built-in equality check and requires the signers to communicate through secure channels.
The variant of SimplPedPop specified here is tailored for scenarios involving an untrusted coordinator, which enables bandwidth optimizations and is common also in implementations of the signing stage of FROST.

Our design then follows a layered approach:
We first wrap SimplPedPop in a protocol EncPedPop responsible not only for encrypting shares but also for authenticity, which is established via the equality check protocol.
Consequently, unlike SecPedPop, EncPedPop does not require pre-existing secure channels between the signers.
The encryption relies on pairwise ECDH key exchanges between the signers.

We then wrap EncPedPop in a second protocol RecPedPop that implements an equality check protocol.
Our equality check protocol is an extension of the Goldwasser-Lindell echo broadcast [GW05] protocol
and features "success certificates":
whenever some honest signer considers the DKG to be successful
this honest signer can, ultimately at the time of a signing request, convince all other honest signers that the DKG has indeed been successful.

As an additional feature of RecPedPop, the state of any signing device can be fully recovered from a backup of a single secret per-device seed and the full public transcripts of all the DKG runs in which the device was involved.
RecPedPop thus incorporates solutions for both secure channels and broadcast, and simplifies backups in practice.

As a result, RecPedPop is our primary recommendation that fits a wide range scenarios,
and due to its low overhead, we recommend RecPedPop even for applications which already have secure channels or have access to an external broadcast mechanism such as a BFT protocol.
Nevertheless, such applications may wish to use the low-level variants SimplPedPop and EncPedPop in special cases.

|                 | seed              | requires secure channels | equality check protocol included | backup                             | Recommended  |
|-----------------|-------------------|--------------------------|----------------------------------|------------------------------------|--------------|
| **SimplPedPop** | fresh             | yes                      | no                               | share per setup                    | no           |
| **EncPedPop**   | reuse allowed     | no                       | no                               | share per setup                    | yes, with Eq |
| **RecPedPop**   | reuse for backups | no                       | yes                              | seed + public transcript per setup | yes          |

In summary, we aim for the following design goals:

TODO: We could also mention (conditional) agreement and that it prevents losing coins, because it may not be a property supported by all DKGs. Also could mention "Modularity" since it's possible to wrap SimplPedPop in some other protocol.
TODO: We should improve distinction between features of EncPedPop and RecPedPop

- **Standalone**: The RecPedPop DKG protocol is fully specified, requiring no pre-existing secure channels or a broadcast mechanism.
- **Dishonest Majority**: The three DKGs presented here support any threshold `t <= n` (including "dishonest majority" `t > n/2`).
- **Flexibility**: The three DKGs presented here support a wide range of scenarios, from those where the signing devices are owned and connected by a single individual, to scenarios where multiple owners manage the devices from distinct locations. Moreover, they support situations where backup information is required to be written down manually, as well as those with ample backup space.
- **Simple backups**: The capability of RecPedPop to recover from a static seed and public per-setup data impacts the user experience when backing up threshold-signature wallets. This can enhance the probability of having backups available, preventing users from losing access to their wallets.
- **Support for Coordinator**: As in the FROST signing protocol, all three DKG protocols presented here support a coordinator who can relay messages between the peers. This reduces communication overhead, because the coordinator is able to aggregate some some messages. A malicious coordinator can force the DKG to fail but cannot negatively affect the security of the DKG.
- **DKG outputs per-participant public keys**: When DKG is used in FROST, this allows partial signature verification.

As a consequence of above design goals, the DKG protocols inherit the following limitations:

- **No robustness**: Misbehaving signers can prevent the protocol from completing successfully. In such cases it is not possible to identify who of the signers misbehaved (unless they misbehave in certain trivial ways).
- **Communication complexity not optimal in all scenarios**: While the DKG protocols presented here are optimized for bandwidth efficiency and number of rounds under the premise of flexibility, there are conceivable scenarios where alternative protocols may have better communication complexity.

### Backup and Recovery

Losing the secret share or the shared public key will render the signer incapable of producing signatures.
These values are the output of the DKG and therefore, cannot be derived from a seed - unlike secret keys in BIP 340 or BIP 327.
In many scenarios, it is highly recommended to have a backup strategy to recover the outputs of the DKG.
The recommended strategies are described in the EncPedPop and RecPedPop Backup and Recovery sections.
TODO: consider mentioning that backups are not always necessary

TODO: make the following a footnote
There are strategies to recover if the backup is lost and other signers assist in recovering.
In such cases, the recovering signer must be very careful to obtain the correct secret share and shared public key!
1. If all other signers are cooperative and their seed is backed up (EncPedPop or RecPedPop), it's possible that the other signers can recreate the signer's lost secret share.
2. If threshold-many signers are cooperative, they can use the "Enrolment Repairable Threshold Scheme" described in [these slides](https://github.com/chelseakomlo/talks/blob/master/2019-combinatorial-schemes/A_Survey_and_Refinement_of_Repairable_Threshold_Schemes.pdf).
   This scheme requires no additional backup or storage space for the signers.
These strategies are out of scope for this document.

## Preliminaries

### Notation

We assume the participants agree on an assignment of indices `0` to `n-1` to participants. TODO: mention that there's also a coordinator, which may be a participant

* The function `chan_send(m)` sends message `m` to the coordinator.
* The function `chan_receive()` returns the message received by the coordinator.
* The function `chan_receive_from(i)` returns the message received by participant `i`.
* The function `chan_send_to(i, m)` sends message `m` to participant `i`.
* The function `chan_send_all(m)` sends message `m` to all participants.
* The function `point_add_multi(points)` performs the group operation on the given points and returns the result.
* The function `sum_scalar(scalars)` sums scalars modulo `GROUP_ORDER` and returns the result.
* The function `individual_pk(sk)` is identical to the BIP 327 `IndividualPubkey` function.
* The function `verify_sig(m, pk, sig)` is identical to the BIP 340 `Verify` function.
* The function `sign(m, sk)` is identical to the BIP 340 `Sign` function.

```python
biptag = "BIP DKG: "

def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(biptag + tag, msg)

def kdf(seed, tag, extra_input):
    # TODO: consider different KDF
    return tagged_hash_bip_dkg(tag + "KDF ", seed + extra_input)

```

### Verifiable Secret Sharing (VSS)

```python
def point_add_multi(points: List[Optional[Point]]) -> Optional[Point]:
    acc = None
    for point in points:
        acc = point_add(acc, point)
    return acc

# A scalar is represented by an integer modulo GROUP_ORDER
Scalar = int

# A polynomial is represented by a list of coefficients
# f(x) = coeffs[0] + ... + coeff[n] * x^n
Polynomial = List[Scalar]

# Evaluates polynomial f at x
def polynomial_evaluate(f: Polynomial, x: Scalar) -> Scalar:
   value = 0
   # Reverse coefficients to compute evaluation via Horner's method
   for coeff in f[::-1]:
        value = (value * x) % GROUP_ORDER
        value = (value + coeff) % GROUP_ORDER
   return value

# Returns [f(1), ..., f(n)] for polynomial f with coefficients coeffs
def secret_share_shard(f: Polynomial, n: int) -> List[Scalar]:
    return [polynomial_evaluate(f, x_i) for x_i in range(1, n + 1)]

# A VSS Commitment is a list of points
VSSCommitment = List[Point]

# Returns commitments to the coefficients of f. The coefficients must be
# non-zero.
def vss_commit(f: Polynomial) -> VSSCommitment:
    vss_commitment = []
    for coeff in f:
        A_i = point_mul(G, coeff)
        assert(A_i is not None)
        vss_commitment.append(A_i)
    return vss_commitment

def vss_verify(signer_idx: int, share: Scalar, vss_commitment: VSSCommitment) -> bool:
     P = point_mul(G, share)
     Q = [point_mul(vss_commitment[j], pow(signer_idx + 1, j) % GROUP_ORDER) \
          for j in range(0, len(vss_commitment))]
     return P == point_add_multi(Q)

VSSCommitmentSum = List[Union[Optional[Point], bytes]]

# Sum the commitments to the i-th coefficients from the given vss_commitments
# for i > 0. This procedure is introduced by Pedersen in section 5.1 of
# 'Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing'.
def vss_sum_commitments(vss_commitments: List[Tuple[VSSCommitment, bytes]], t: int) -> VSSCommitmentSum:
    n = len(vss_commitments)
    assert(all(len(vss_commitment[0]) == t for vss_commitment in vss_commitments))
    # The returned array consists of 2*n + t - 1 elements
    # [vss_commitments[0][0][0], ..., vss_commitments[n-1][0][0],
    #  sum_group(vss_commitments[i][1]), ..., sum_group(vss_commitments[i][t-1]),
    #  vss_commitments[0][1], ..., vss_commitments[n-1][1]]
    return [vss_commitments[i][0][0] for i in range(n)] + \
           [point_add_multi([vss_commitments[i][0][j] for i in range(n)]) for j in range(1, t)] + \
           [vss_commitments[i][1] for i in range(n)]

# Outputs the shared public key and individual public keys of the participants
def derive_group_info(vss_commitment: VSSCommitment, n: int, t: int) -> Tuple[Optional[Point], List[Optional[Point]]]:
  pk = vss_commitment[0]
  participant_public_keys = []
  for signer_idx in range(0, n):
    pk_i = point_add_multi([point_mul(vss_commitment[j], pow(signer_idx + 1, j) % GROUP_ORDER) \
                            for j in range(0, len(vss_commitment))])
    participant_public_keys += [pk_i]
  return pk, participant_public_keys
```

## DKG Protocols

For each signer, the DKG has three outputs: a secret share, the shared public key, and individual public keys for partial signature verification.
The secret share and shared public key are required by a signer to produce signatures and therefore, signers *must* ensure that they are not lost.
We refer to the [Backup and Recovery](#backup-and-recovery) section for additional details.

TODO: mention that these are properties when using the DKG with FROST
If a DKG run succeeds from the point of view of an honest signer by outputting a shared public key,
then unforgeability is guaranteed, i.e., no subset of `t-1` signers can create a signature.
TODO: Additionally, all honest signers receive correct DKG outputs, i.e., any set of t honest signers is able to create a signature.
TODO: consider mentioning ROAST


### SimplPedPop

TODO: introduce as building block for EncPedPop/RecPedPop instead of as its own thing
We specify the SimplPedPop scheme as described in
[Practical Schnorr Threshold Signatures Without the Algebraic Group Model, section 4](https://eprint.iacr.org/2023/899.pdf)
with the following minor modifications:

- Adding individual's signer public keys to the output of the DKG. This allows partial signature verification.
- Very rudimentary ability to identify misbehaving signers in some situations.
- The proof-of-knowledge in the setup does not commit to the prover's ID. This is slightly simpler because it doesn't require the setup algorithm to take the ID as input.
- The participants send VSS commitments to an untrusted coordinator instead of directly to each other. This lets the coordinator aggregate VSS commitments, which reduces communication cost.

SimplPedPop requires SECURE point-to-point channels for transferring secret shares between participants - that is, channels that are both ENCRYPTED and AUTHENTICATED.
These messages can be relayed through the coordinator who is responsible to pass the messages to the participants as long as the coordinator cannot interfere with the secure channels between the participants.

Also, SimplePedPop requires an interactive equality check protocol `Eq` as described in section [Equality Protocol](#equality-protocol).
While SimplPedPop is able to identify participants who are misbehaving in certain ways, it is easy for a participant to misbehave such that it will not be identified.

In SimplPedPop, the signers designate a coordinator who relays and aggregates messages.
Every participant runs the `simplpedpop` algorithm and the coordinator runs the `simplpedpop_coordinate` algorithm as described below.

```python
SimplePedPopR1State = Tuple[int, int]
VSS_PoK_msg = (biptag + "VSS PoK").encode()

def simplpedpop_round1(seed: bytes, t: int, n: int) -> Tuple[SimplePedPopR1State, Tuple[VSSCommitment, bytes], List[Scalar]]:
    """
    Start SimplPedPop by generating messages to send to the other participants.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param int n: number of participants
    :return: a state, a VSS commitment and shares
    """
    coeffs = [kdf(seed, "coeffs", i) for i in range(t)]
    sig = sign(VSS_PoK_msg, coeffs[0], kdf(seed, "VSS PoK", ""))
    # FIXME make sig a separate thing
    my_vss_commitment = (vss_commit(coeffs), sig)
    my_generated_shares = secret_share_shard(coeffs, n)
    state = (t, n)
    return state, my_vss_commitment, my_generated_shares

class InvalidContributionError(Exception):
    def __init__(self, signer, error):
        self.signer = signer
        self.contrib = error

def simplpedpop_finalize(state: SimplePedPopR1State, my_idx: int,
                         vss_commitments_sum: VSSCommitmentSum, shares_sum: Scalar,
                         Eq: Callable[[Any],bool] , eta: Any = ()) \
                         -> Union[Tuple[Scalar, Optional[Point], List[Optional[Point]]], bool]:
    """
    Take the messages received from the participants and finalize the DKG

    :param int my_idx:
    :param List[bytes] vss_commitments_sum: output of running vss_sum_commitments() with vss_commitments from all participants (including this participant) (TODO: not a list of bytes)
    :param scalar shares_sum: summed shares from all participants (including this participant) for this participant mod group order
    :param eta: Optional argument for extra data that goes into `Eq`
    :return: a final share, the shared pubkey, the individual participants' pubkeys
    """
    t, n = state
    assert(len(vss_commitments_sum) == 2*n + t - 1)
    for i in range(n):
        assert(isinstance(vss_commitments_sum[i], Point))
        pk_i = bytes_from_point(vss_commitments_sum[i])
        if not verify_sig(VSS_PoK_msg, pk_i, vss_commitments_sum[n + t-1 + i]):
            raise InvalidContributionError(i, "Participant sent invalid proof-of-knowledge")
    eta += (vss_commitments_sum)
    # Strip the signatures and sum the commitments to the constant coefficients
    vss_commitments_sum_coeffs = [point_add_multi([vss_commitments_sum[i] for i in range(n)])] + vss_commitments_sum[n:n+t-1]
    if not vss_verify(my_idx, vss_commitments_sum_coeffs, shares_sum):
        return False
    if not Eq(eta):
        return False
    shared_pubkey, signer_pubkeys = derive_group_info(vss_commitments_sum_coeffs, n, t)
    return shares_sum, shared_pubkey, signer_pubkeys
```

### EncPedPop

EncPedPop is identical to SimplPedPop except that it does not require secure channels between the participants.
Every EncPedPop participant runs the `encpedpop` algorithm and the coordinator runs the `encpedpop_coordinate` algorithm as described below.

#### Encryption

```python
def ecdh(x, Y, context):
    return tagged_hash("ECDH", x*Y, context)

def encrypt(share, my_deckey, enckey, context):
    return (share + ecdh(my_deckey, enckey, context)) % GROUP_ORDER
```

#### Wrapping SimplPedPop

The participants start by generating an ephemeral key pair as per [BIP 327's IndividualPubkey](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-generation-of-an-individual-signer) for encrypting the 32-byte key shares.

```python
def encpedpop_round1(seed):
    my_deckey = kdf(seed, "deckey")
    my_enckey = individual_pk(my_deckey)
    state1 = (my_deckey, my_enckey)
    return state1, my_enckey
```

The (public) encryption keys are distributed among the participants.

```python
def encpedpop_round2(seed, state1, t, n, enckeys):
    assert(n == len(enckeys))
    if len(enckeys) != len(set(enckeys)):
        raise DuplicateEnckeysError

    my_deckey, my_enckey = state1
    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    seed_ = tagged_hash("encpedpop seed", seed, t, enckeys)
    simpl_state, vss_commitment, shares = simplpedpop_round1(seed_, t, n)
    enc_context = hash([t] + enckeys)
    enc_shares = [encrypt(shares[i], my_deckey, enckeys[i], enc_context) for i in range(len(enckeys))
    state2 = (t, my_deckey, my_enckey, enckeys, simpl_state)
    return state2, vss_commitment, enc_shares

def encpedpop_finalize(state2, vss_commitments_sum, enc_shares_sum, Eq, eta = ()):
    t, my_deckey, my_enckey, enckeys, simpl_state = state2
    n = len(enckeys)
    assert(len(vss_commitments_sum) == 2*n + t - 1)

    enc_context = hash([t] + enckeys)
    shares_sum = enc_shares_sum - sum_scalar([ecdh(my_deckey, enckeys[i], enc_context) for i in range(n)]
    try:
        my_idx = enckeys.index(my_enckey)
    except ValueError:
        raise BadCoordinatorError("Coordinator sent list of encryption keys that does not contain our key.")
    eta += (enckeys)
    simplpedpop_finalize(simpl_state, my_idx, vss_commitments_sum, shares_sum, Eq, eta):
```

Note that if the public keys are not distributed correctly or the messages have been tampered with, `Eq(eta)` will fail.

```python
def encpedpop(seed, t, n, Eq):
    state1, my_enckey = encpedpop_round1(seed):
    chan_send(my_enckey)
    enckeys = chan_receive()

    state2, my_vss_commitment, my_generenckeys = encpedpop_round2(seed, state1, t, n, enckeys)
    chan_send((my_vss_commitment, my_generated_enc_shares))
    vss_commitments_sum, enc_shares_sum = chan_receive()

    return encpedpop_finalize(state2, vss_commitments_sum, enc_shares_sum, Eq)

# TODO: explain that it's possible to arrive at the global order of signer indices by sorting enckeys

# TODO: We would actually have to parse the received network messages. This
# should include parsing of the group elementsas well as checking that the
# length of the lists is correct (e.g. vss_commitments are of length t) and
# allow to identify bad participants/coordinator instead of running into
# assertions.

def encpedpop_coordinate_internal(t, n):
    vss_commitments = []
    enc_shares_sum = (0)*n
    for i in range(n)
        vss_commitment, enc_shares = [chan_receive_from(i)]
        vss_commitments += [vss_commitment]
        enc_shares_sum = [ enc_shares_sum[j] + enc_shares[j] for j in range(n) ]
    vss_commitments_sum = vss_sum_commitments(vss_commitments, t)
    return vss_commitments_sum, enc_shares_sum

def encpedpop_coordinate(t, n):
    vss_commitments_sum, enc_shares_sum = encpedpop_coordinate_internal(t, n)
    for i in range(n)
        chan_send_to(i, (vss_commitments_sum, enc_shares_sum[i]))
```

#### Backup and Recovery

There are two possible backup strategies for `EncPedPop`:

1. **Backup of the secret shares**
    Backups consist of the signer index and DKG outputs: secret share and shared public key.
    It is possible to only back up the secret share, but then the shared public key and index needs to be provided to complete a recovery (TODO: what if the public key and index are wrong?).
    This data needs to be backed up for every DKG the signer is involved in.
    The backup needs to be stored securely: anyone obtaining the backup has stolen all the data necessary to create partial signatures just as the victim signer.
2. **Backup of the seed and encrypted shares**
    It is also possible to back up the seed in a secure location and back up the encrypted shares.
    ```python
    # All inputs of this function are required to be backed up for full recovery
    # With the exception of seed, they are public data
    def encpedpop_recover(seed, enc_shares_sum, t, enckeys, shared_pubkey, signer_pubkeys):
        my_deckey = kdf(seed, "deckey")
        enc_context = hash([t] + enckeys)
        shares_sum = enc_shares_sum - sum_scalar([ecdh(my_deckey, enckeys[i], enc_context) for i in range(n)]
        return shares_sum, shared_pubkey, signer_pubkeys

    # my_idx is required for signing
    def encpedpop_recover_my_idx(seed, enc_shares_sum, t, enckeys, shared_pubkey, signer_pubkeys):
        return enckeys.index(my_enckey)
    ```
    If the encrypted shares are lost and all other signers are cooperative and have seed backups, then there is also the possibility to re-run the DKG.

### RecPedPop

RecPedPop is a wrapper around EncPedPop which also includes the built-in equality check protocol `certifying_Eq`.
Its advantage is that recovering a signer is securely possible from a single seed and the full transcript of the protocol.
Since the transcript is public, every signer (and the coordinator) can store it to help recover any other signer.

Generate long-term host keys.

```python
def recpedpop_hostpubkey(seed):
    my_hostsigkey = kdf(seed, "hostsigkey")
    my_hostverkey = individual_pk(hostsigkey)
    return (my_hostsigkey, my_hostverkey)
```

The participants send their host pubkey to the other participant and collect received host pubkeys.
They then compute a setup identifier that includes all participants (including yourself TODO: this is maybe obvious but probably good to stress, in particular for backups).

```python
def recpedpop_setup_id(hostverkeys, t, context_string):
    setup_id = tagged_hash("setup id", hostverkeys, t, context_string)
    setup = (hostverkeys, t, setup_id)
    return setup, setup_id
```

The participants compare the setup identifier with every other participant out-of-band.
If some other participant presents a different setup identifier, the participant aborts.

```python
def recpedpop_round1(seed, setup):
    hostverkeys, t, setup_id = setup

    # Derive setup-dependent seed
    seed_ = kdf(seed, "setup", setup_id)

    enc_state1, my_enckey =  encpedpop_round1(seed_)
    state1 = (hostverkeys, t, setup_id, enc_state1, my_enckey)
    return state1, my_enckey
```

```python
def recpedpop_round2(seed, state1, enckeys):
    hostverkeys, t, setup_id, enc_state1, my_enckey = state1

    enc_state2, vss_commitment, enc_shares = encpedpop_round2(seed_, enc_state1, t, n, enckeys)
    my_idx = enckeys.index(my_enckey)
    state2 = (setup_id, my_idx, enc_state2)
    return state2, hostverkeys, vss_commitment, enc_shares
```

```python
def recpedpop_finalize(seed, state2, vss_commitments_sum, all_enc_shares_sum, Eq):
    (setup_id, my_idx, enc_state2) = state2

    # TODO Not sure if we need to include setup_id as eta here. But it won't hurt.
    # Include the enc_shares in eta to ensure that participants agree on all
    # shares, which in turn ensures that they have the right transcript.
    # TODO This means all parties who hold the "transcript" in the end should
    # participate in Eq?
    eta = (setup_id, all_enc_shares_sum)
    my_enc_shares_sum = all_enc_shares_sum[my_idx]
    return encpedpop_finalize(enc_state2, vss_commitments_sum, my_enc_shares_sum, Eq, eta)
```

```python
def recpedpop(seed, my_hostsigkey, setup):
    state1, my_enckey = recpedpop_round1(seed, setup)
    chan_send(my_enckey)
    enckeys = chan_receive()

    state2, hostverkeys, my_vss_commitment, my_generated_enc_shares =  recpedpop_round2(seed, state1, enckeys)
    chan_send((my_vss_commitment, my_generated_enc_shares))
    vss_commitments, enc_shares_sum = chan_receive()

    shares_sum, shared_pubkey, signer_pubkeys = recpedpop_finalize(seed, state2, vss_commitments_sum, enc_shares_sum, make_certifying_Eq(my_hostsigkey, hostverkeys))
    transcript = (setup, enckeys, vss_commitments_sum, enc_shares_sum, result["cert"])
    return shares_sum, shared_pubkey, signer_pubkeys, transcript

def recpedpop_coordinate(t, n):
    vss_commitments_sum, enc_shares_sum = encpedpop_coordinate_internal(t, n)
    chan_send_all((vss_commitments_sum, enc_shares_sum))
```

#### Certifying equality check protocol based on Goldwasser-Lindell Echo Broadcast

TODO The hpk should be the id here... clean this up and write something about setup assumptions

The equality check of RecPedPop is instantiated by the following protocol:

```python
def verify_cert(hostverkeys, x, sigs):
    if len(sigs) != len(hostverkeys):
        return False
    is_valid = [verify_sig(hostverkeys[i], x, sigs[i]) for i in range(hostverkeys)]
    return all(is_valid)

def make_certifying_Eq(my_hostsigkey, hostverkeys, result):
    def certifying_Eq(x):
        chan_send(("SIG", sign(my_hostsigkey, x)))
        sigs = [None] * len(hostverkeys)
        while(True)
            i, ty, msg = chan_receive()
            if ty == "SIG":
                is_valid = verify_sig(hostverkeys[i], x, msg)
                if sigs[i] is None and is_valid:
                    sigs[i] = msg
                elif not is_valid:
                    # The signer `hpk` is either malicious or an honest signer
                    # whose input is not equal to `x`. This means that there is
                    # some malicious signer or that some messages have been
                    # tampered with on the wire. We must not abort, and we could
                    # still output True when receiving a cert later, but we
                    # should indicate to the user (logs?) that something went
                    # wrong.)
                if sigs.count(None) == 0:
                    cert = sigs
                    result["cert"] = cert
                    for i in range(n):
                        chan_send(("CERT", cert))
                    return True
            if ty == "CERT":
                sigs = msg
                if verify_cert(hostverkeys, x, sigs):
                    result["cert"] = cert
                    for i in range(n):
                        chan_send(("CERT", cert))
                    return True
    return certifying_eq

def certifying_Eq_coordinate():
    while(True):
        for i in range(n):
            ty, msg = chan_receive_from(i)
            chan_send_all((i, ty, msg))
```

In practice, the certificate can also be attached to signing requests instead of sending it to every participant after returning True.
It may still be helpful to check with other participants out-of-band that they have all arrived at the True state. (TODO explain)

![recpedpop diagram](images/recpedpop-sequence.png)


#### Backup and Recovery

A `RecPedPop` backup consists of the seed and the DKG transcript.
The seed can be reused for multiple DKGs and must be stored securely.
On the other hand, DKG transcripts are public and allow to re-run above RecPedPop algorithms to obtain the DKG outputs.

```python
# Recovery requires the seed and the public transcript
def recpedpop_recover(seed, transcript):
    my_hostsigkey, _ = recpedpop_hostpubkey(seed)
    setup, enckeys, vss_commitments_sum, enc_shares_sum, cert = transcript

    state1, my_enckey = recpedpop_round1(seed, setup)
    state2, my_vss_commitment, my_generated_enc_shares =  recpedpop_round2(seed, state1, enckeys)

    def Eq(x):
        return verify(hostverkeys, x, cert)
    shares_sum, shared_pubkey, signer_pubkeys = recpedpop_finalize(seed, my_hostsigkey, state2, vss_commitments_sum, enc_shares_sum, Eq)
    return shares_sum, shared_pubkey, signer_pubkeys
```

In contrast to the encrypted shares backup strategy of `EncPedPop`, all the non-seed data that needs to be backed up is the same for all signers. Hence, if a signer loses the backup of the DKG transcript, they can request it from the other signers.

## Equality Check Protocol

TODO: The term agreement is overloaded (used for formal property of Eq and for informal property of DKG). Maybe rename one to consistency? Check the broadcast literature first

A crucial prerequisite for security is that participants reach agreement over the results of the DKG.
Indeed, disagreement may lead to catastrophic failure:
For example, assume that all but one participant believe that DKG has failed and therefore delete their secret key material,
but one participant believes that the DKG has finished successfully and sends funds to the resulting threshold public key.
Then those funds will be lost irrevocably, because, assuming `t > 1`, the single remaining secret share is not sufficient to produce a signature.

DKG protocols in the cryptographic literature often abstract away from this problem
by assuming that all participants have access to some kind of ideal "reliable broadcast" mechanism, which guarantees that all participants receive the same protocol messages and thereby ensures agreement.
However, it can be hard or even theoretically impossible to realize a reliable broadcast mechanism depending on the specifics of the application scenario, e.g., the guarantees provided by the underlying network, and the minimum number of participants assumed to be honest.

The DKG protocols described in this document work with a similar but slightly weaker abstraction instead.
They assume that participants have access to an equality check mechanism "Eq", i.e.,
a mechanism that asserts that the input values provided to it by all participants are equal.

TODO: Is it really the DKG that is successful here or is it just Eq?

Eq has the following abstract interface:
Every participant can invoke Eq(x) with an input value x.
Eq may not return at all to the calling participant, but if it returns, it will return True (indicating success) or False (indicating failure).
 - True means that it is guaranteed that all honest participants agree on the value x (but it may be the case that not all of them have established this fact yet). This means that the DKG was successful and the resulting aggregate key can be used, and the generated secret keys need to be retained.
 - False means that it is guaranteed that no honest participant will output True. In that case, the generated secret keys can safely be deleted.

As long as Eq(x) has not returned for some participant, this participant remains uncertain about whether the DKG has been successful or will be successful.
In particular, such an uncertain participant cannot rule out that other honest participants receive True as a return value and thus conclude that the DKG keys can be used.
As a consequence, even if Eq appears to be stuck, the caller must not assume (e.g., after some timeout) that Eq has failed, and, in particular, must not delete the DKG state and the secret key material.

TODO Add a more concrete example with lost funds that demonstrates the risk?

While we cannot guarantee in all application scenarios that Eq() terminates and returns, we can typically achieve a weaker guarantee that covers agreement in the successful cases.
Under the assumption that network messages eventually arrive (this is often called an "asynchronous network"), we can guarantee that if *some* honest participant determines the DKG to be successful, then *all* other honest participants determine it to be successful eventually.

More formally, Eq must fulfill the following properties:
 - Integrity: If some honest participant outputs True, then for every pair of values x and x' input provided by two honest participants, we have x = x'.
 - Conditional Agreement: If some honest participant outputs True and the delivery of messages between honest participants is guaranteed, then all honest participants output True.

Conditional agreement does *not* guarantee that the protocol terminates if two honest participants have `x` and `x'` such that `x != x'`.
To ensure termination in that situation, the protocol requires a stronger property:
 - (Full) Agreement: If the delivery of messages between honest participants is guaranteed, all honest participants will output True or False.

### Examples

TODO: Expand these scenarios. Relate them to True, False.

Depending on the application scenario, Eq can be implemented by different protocols, some of which involve out-of-band communication:

#### Participants are in a single room

In a scenario where a single user employs multiple signing devices (e.g., hardware wallets) in the same room to establish a threshold setup, every device can simply display its value x (or a hash of x under a collision-resistant hash function) to the user. The user can manually verify the equality of the values by comparing the values shown on all displays, and confirm their equality by providing explicit confirmation to every device, e.g., by pressing a button on every device.

TODO add failure case, specify entire protocol

Similarly, if signing devices are controlled by different organizations in different geographic locations, agents of these organizations can meet in a single room and compare the values.

These "out-of-band" methods can achieve agreement (assuming the involved humans proceed with their tasks eventually).

#### Certifying network-based protocol based on Goldwasser-Lindell Echo Broadcast

The [equality check protocol used by RecPedPop](#certifying-equality-check-protocol-based-on-goldwasser-lindell-echo-broadcast) is applicable to network-based scenarios where long-term host keys are available. It satisfies integrity and conditional agreement.

Proof. (TODO for footnote?)
Integrity:
Unless a signature has been forged, if some honest participant with input `x` outputs True,
then by construction, all other honest participants have sent a signature on `x` and thus received `x` as input.
Conditional Agreement:
If some honest participant with input `x` returns True,
then by construction, this participant sends a list `cert` of valid signatures on `x` to every other participant.
Consider any honest participant among these other participants.
Assuming a reliable network, this honest participant eventually receives `cert`,
and by integrity, has received `x` as input.
Thus, this honest participant will accept `cert` and return True.

#### Consensus protocol

If the participants run a BFT-style consensus protocol (e.g., as part of a federated protocol), they can use consensus to check whether they agree on `x`.

TODO: Explain more here. This can also achieve agreement but consensus is hard (e.g., honest majority, network assumptions...)
