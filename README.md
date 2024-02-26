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

An interactive *distributed key generation* (DKG) protocol session by all signers avoids the need for a trusted dealer.
There exist a number of DKG protocols with different requirements and guarantees.
Most suitably for the use with FROST is the PedPop DKG (``Pedersen DKG with proofs of possession'') [KG20, CKM21, CGRS23].
But similar to most DKG protocols in the literature, PedPop has strong requirements on the communication between participants,
which make it difficult to deploy PedPop in practice.
It assumes that signers have secure (i.e., authenticated and encrypted) channels between each other to deliver secret shares to individual signers,
and it assumes that signers have access to a secure broadcast mechanism.
 - TODO Explain how funds are lost if broadcast doesn't work.

The aim of this document is to describe *ChillDKG*, a variant of PedPop with "batteries included",
i.e., it incorporates minimal but sufficient implementations of secure channels and secure broadcast
and thus is easy to deploy in practice.

### Design

The basic building block of our DKG protocol is the SimplPedPop protocol, which has been proven to be secure when combined with FROST [CGRS23].
The variant of SimplPedPop considered here is tailored for scenarios involving an untrusted coordinator, which enables bandwidth optimizations and is common also in implementations of the signing stage of FROST.

TODO: Say something about dishonest majority here, not only in the list below.

Besides external secure channels, SimplPedPod depends on an external *equality check protocol*.
The equality check protocol serves an abstraction of a secure broadcast mechanism with limited functionality (TODO: this may be a confusing way to introduce the realtionship between equality check and broadcast. E.g., it doesn't only have limited functionality, it has more functionality as in broadcast only a single party broadcasts):
Its only purpose is to check that, at the end of SimplPedPod, all participants have established an identical protocol transcript.

Our goal is to turn SimplPedPop into a standalone DKG protocol without external dependencies.
We follow a modular approach that removes one dependency at a time.
First, we take care of secure channels by wrapping SimplPedPop in a protocol EncPedPop,
which relies on pairwise ECDH key exchanges between the participants to encrypt secret shares.
Finally, we add a concrete equality check protocol to EncPedPop to obtain a standalone DKG protocol ChillDKG.

Our equality check protocol is inspired by the Goldwasser-Lindell echo broadcast [GW05] protocol.
Crucially, it ensures that
whenever some participant obtains a threshold public key as output of a successful DKG session,
this honest participant will additionally obtain a transferable "success certificate",
which can convince all other honest participants
(ultimately at the time of a signing request)
that the DKG has indeed been successful.
This is sufficient to exclude the bad scenario described in the previous section. (TODO)

As an additional feature of ChillDKG, the state of any signing device can be fully recovered from a backup of a single secret per-device seed and the full public transcripts of all the DKG sessions in which the device was involved.
ChillDKG thus incorporates solutions for both secure channels and broadcast, and simplifies backups in practice.

In summary, ChillDKG fits a wide range of usage scenarios,
and due to its low overhead, we recommend ChillDKG even for applications which already incorporate secure channels or an existing broadcast mechanism such as a BFT protocol.


TODO: We could also mention (conditional) agreement and that it prevents losing coins, because it may not be a property supported by all DKGs. Also could mention "Modularity" since it's possible to wrap SimplPedPop in some other protocol.

In summary, we aim for the following design goals:

- **Standalone**: ChillDKG is fully specified, requiring no pre-existing secure channels or a broadcast mechanism.
- **Dishonest Majority**:  ChillDKG supports any threshold `t <= n` (including "dishonest majority" `t > n/2`).
- **Flexibility**:  ChillDKG supports a wide range of scenarios, from those where the signing devices are owned and connected by a single individual, to scenarios where multiple owners manage the devices from distinct locations.
- **Simple backups**: The capability of ChillDKG to recover from a static seed and public per-setup data impacts the user experience when backing up threshold-signature wallets. This can enhance the probability of having backups available, preventing users from losing access to their wallets.
- **Support for Coordinator**: Like the FROST signing protocol, ChillDKG supports a coordinator who can relay messages between the participants. This reduces communication overhead, because the coordinator is able to aggregate some some messages. A malicious coordinator can force the DKG to fail but cannot negatively affect the security of the DKG.
- **DKG outputs per-participant public keys**: When ChillDKG is used with FROST, partial signature verification is supported.

As a consequence of these design goals, ChillDKG inherit the following limitations:

- **No robustness**: Misbehaving signers can prevent the protocol from completing successfully. In such cases it is not possible to identify who of the signers misbehaved (unless they misbehave in certain trivial ways).
- **Communication complexity not optimal in all scenarios**: While ChillDKG is optimized for bandwidth efficiency and number of rounds under the premise of flexibility, there are conceivable scenarios where specialized protocols may have better communication complexity, e.g., when setting up multiple signing devices in a single location.

## Preliminaries

### Protocol Roles and Network Setup

There are `n >= 2` *signers*, `t` of which will be required to produce a signature.
Each signer has a point-to-point communication link to the *coordinator*
(but signers do not have direct communication links to each other).

If there is no dedicated coordinator, one of the signers can act as the coordinator.
(TODO This is like in MuSig, but we explained this differently in BIP327 where we say that the coordinator is optional...)

### Threat Model and Security Goals

Some signers, the coordinator and all network links may be malicious, i.e., controlled by an attacker.
We expect ChillDKG to provide the following informal security goals when it is used to setup keys for the FROST threshold signature scheme.
(See TODO for a more formal treatment.)

If a session of the DKG protocol returns an output to an (honest) signer,
then we say that this signer *deems the protocol session successful*.
In that case, the output returned by the protocol session to the signer is a tuple consisting of a *secret share* (individual to the signer), the *shared public key* (common to all signers), a list of n *individual public keys* for partial signature verification (common to all signers), and a *success certificate* (common to all signers).

If a signer deems a protocol session successful, then this signer is assured that:
 - A coalition of a malicious coordinator and at most `t - 1` malicious signers cannot forge signatures under that shared public key. (Unforgeability)
 - All (honest) signers who deem the protocol session successful will have correct and consistent protocol outputs.
   In particular, they agree on the shared public key, the list of individual public keys and the success certificate.
   Moreover, any `t` of them have secret shares which are, in principle, sufficient to reconstruct the secret key corresponding to the shared public key.
   This means that any `t` of have all the necessary inputs to session a successful FROST signing sessions that produce signatures valid under the shared public key.
 - The success certificate will, when presented to any other (honest) signer, convince that other signer to deem the protocol successful.

We stress that the mere fact one signer deems a protocol session successful does not imply that other signers deem it successful yet.
That is exactly why the success certificate is necessary:
If some signers have deemed the protocol not successful, but others have not (yet) and thus are stuck in the protocol session,
e.g., due to failing network links or invalid messages sent by malicious signers,
the successful signers can eventually make the stuck signers unstuck
by presenting them a success certificate.
The success certificate can, e.g., be attached to a request to initiate a FROST signing session.

## Building Blocks

We start by providing Python code for low-level building blocks of ChillDKG,
namely Feldman's Verifiable Secret Sharing (VSS) scheme, and parts of the DKG protocol SimplPedPop and EncPedPod.
**This is not meant to endorse direct use of VSS, or of SimplPedPop or EncPedPod as DKG protocols.**
While SimplPedPop and EncPedPop may in principle serve as building blocks for other DKG designs (e.g., for applications that already incorporate a broadcast mechanism),
this requires careful further consideration, which is not in the scope of this document.
Consequently, we recommend implementations not to expose the algorithms of the building blocks as part of a high-level API targeted towards developers who are not cryptographic experts. (TODO Is this too arrogant? )

To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive computations,
we omit explicit invocations of an interactive equality check protocol.
ChillDKG will take care of invoking the equality check protocol.

### Assumed Functions, Classes and Constants

<!-- This should just reflect the imports in reference.py -->

* The constant `GROUP_ORDER` refers to the order of the elliptic curve secp256k1.
* The constant `G` refers to the base point of secp256k1.
* The elliptic curve group operation is referred to as addition.
* The function `point_mul(x, P)`, where `x` is an integer and `P` is a point, multiplies `x` with `G` and returns the result.
* The function `point_add_multi(Ps)`, where `Ps` is an array of points, adds all `Ps` and returns the result.
* The function `pubkey_gen(sk)` is identical to the BIP 327 `IndividualPubkey` function.
* The function `verify_sig(m, pk, sig)` is identical to the BIP 340 `Verify` function.
* The function `sign(m, sk)` is identical to the BIP 340 `Sign` function.
* The class `SignerChannel` provides the following functions:
    * The function `send(m)` sends message `m` to the coordinator.
    * The function `receive()` returns the message received by the coordinator.
* The class `CoordinatorChannels` provides the following functions:
    * The function `send_all(m)` sends message `m` to all participants.
    * The function `receive_from(i)` returns the message received by participant `i`.


```python
biptag = "BIP DKG: "

def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(biptag + tag, msg)

def kdf(seed: bytes, tag: str, extra_input: bytes = b'') -> bytes:
    # TODO: consider different KDF
    return tagged_hash_bip_dkg(tag + "KDF ", seed + extra_input)
```

### Feldman's Verifiable Secret Sharing (VSS)

```python
# A scalar is represented by an integer modulo GROUP_ORDER
Scalar = int

def scalar_add(x: Scalar, y: Scalar):
    return (x + y) % GROUP_ORDER

# A polynomial of degree t - 1 is represented by a list of t coefficients
# f(x) = a[0] + ... + a[t-1] * x^(t-1)
Polynomial = List[Scalar]

# Evaluates polynomial f at x != 0
def polynomial_evaluate(f: Polynomial, x: Scalar) -> Scalar:
   # From a mathematical point of view, there's nothing wrong with evaluating
   # at position 0. But if we try this in a DKG, we may have a catastrophic
   # bug, because we'd compute the implicit secret.
   assert x != 0

   value = 0
   # Reverse coefficients to compute evaluation via Horner's method
   for coeff in f[::-1]:
        value = (value * x) % GROUP_ORDER
        value = (value + coeff) % GROUP_ORDER
   return value

# Returns [f(1), ..., f(n)] for polynomial f with coefficients coeffs
def secret_share_shard(f: Polynomial, n: int) -> List[Scalar]:
    return [polynomial_evaluate(f, x_i) for x_i in range(1, n + 1)]
```

```python
# A VSS Commitment is a list of points
VSSCommitment = List[Optional[Point]]

# Returns commitments to the coefficients of f
def vss_commit(f: Polynomial) -> VSSCommitment:
    vss_commitment = []
    for coeff in f:
        A_i = point_mul(G, coeff)
        vss_commitment.append(A_i)
    return vss_commitment

def serialize_vss_commitment(vss_commitment: VSSCommitment) -> bytes:
    return b''.join([cbytes_ext(P) for P in vss_commitment])

def deserialize_vss_commitment(b: bytes, t: int) -> VSSCommitment:
    assert(len(b) >= 33*t)
    return [cpoint(b[i:i+33]) for i in range(0, 33*t, 33)]

def vss_verify(signer_idx: int, share: Scalar, vss_commitment: VSSCommitment) -> bool:
    P = point_mul(G, share)
    Q = [point_mul(vss_commitment[j], pow(signer_idx + 1, j) % GROUP_ORDER) \
         for j in range(0, len(vss_commitment))]
    return P == point_add_multi(Q)

# An extended VSS Commitment is a VSS commitment with a proof of knowledge
VSSCommitmentExt = Tuple[VSSCommitment, bytes]

# A VSS Commitment Sum is the sum of multiple extended VSS Commitments
VSSCommitmentSumExt = Tuple[List[Optional[Point]], List[bytes]]

def serialize_vss_commitment_sum(vss_commitment_sum: VSSCommitmentSumExt)-> bytes:
    return b''.join([cbytes_ext(P) for P in vss_commitment_sum[0]]) + b''.join(vss_commitment_sum[1])

# Sum the commitments to the i-th coefficients from the given vss_commitments
# for i > 0. This procedure is introduced by Pedersen in section 5.1 of
# 'Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing'.
def vss_sum_commitments(vss_commitments: List[VSSCommitmentExt], t: int) -> VSSCommitmentSumExt:
    n = len(vss_commitments)
    assert(all(len(vss_commitment[0]) == t for vss_commitment in vss_commitments))
    first_coefficients = [vss_commitments[i][0][0] for i in range(n)]
    remaining_coeffs_sum = [point_add_multi([vss_commitments[i][0][j] for i in range(n)]) for j in range(1, t)]
    poks = [vss_commitments[i][1] for i in range(n)]
    return (first_coefficients + remaining_coeffs_sum, poks)

def vss_commitments_sum_finalize(vss_commitments_sum: VSSCommitmentSumExt, t: int, n: int)-> VSSCommitment:
    # Strip the signatures and sum the commitments to the constant coefficients
    return [point_add_multi([vss_commitments_sum[0][i] for i in range(n)])] + vss_commitments_sum[0][n:n+t-1]

GroupInfo = Tuple[Optional[Point], List[Optional[Point]]]

# Outputs the shared public key and individual public keys of the participants
def derive_group_info(vss_commitment: VSSCommitment, n: int, t: int) -> GroupInfo:
  pk = vss_commitment[0]
  participant_public_keys = []
  for signer_idx in range(0, n):
    pk_i = point_add_multi([point_mul(vss_commitment[j], pow(signer_idx + 1, j) % GROUP_ORDER) \
                            for j in range(0, len(vss_commitment))])
    participant_public_keys += [pk_i]
  return pk, participant_public_keys
```

### SimplPedPop

The SimplPedPop scheme has been proposed in
[Practical Schnorr Threshold Signatures Without the Algebraic Group Model, section 4](https://eprint.iacr.org/2023/899.pdf).
We make the following modifications as compared to the original proposal:
- Adding individual's signer public keys to the output of the DKG. This allows partial signature verification.
- The participants send VSS commitments to an untrusted coordinator instead of directly to each other. This lets the coordinator aggregate VSS commitments, which reduces communication cost.
- The proofs of knowledge are not included in the data for the equality check. This will reduce the size of the backups in ChillDKG.

```python
SimplPedPopR1State = Tuple[int, int, int]
VSS_PoK_msg = (biptag + "VSS PoK").encode()

def simplpedpop_round1(seed: bytes, t: int, n: int, my_idx: int) -> Tuple[SimplPedPopR1State, VSSCommitmentExt, List[Scalar]]:
    """
    Generate SimplPedPop messages to be sent to the coordinator.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param int n: number of participants
    :param int my_idx: index of this signer in the participant list
    :return: the signer's state, the VSS commitment and the generated shares
    """
    assert(t < 2**(4*8))
    coeffs = [int_from_bytes(kdf(seed, "coeffs", i.to_bytes(4, byteorder="big"))) % GROUP_ORDER for i in range(t)]
    assert(my_idx < 2**(4*8))
    # TODO: fix aux_rand
    sig = schnorr_sign(VSS_PoK_msg + my_idx.to_bytes(4, byteorder="big"), bytes_from_int(coeffs[0]), kdf(seed, "VSS PoK"))
    vss_commitment_ext = (vss_commit(coeffs), sig)
    gen_shares = secret_share_shard(coeffs, n)
    state = (t, n, my_idx)
    return state, vss_commitment_ext, gen_shares

DKGOutput = Tuple[Scalar, Optional[Point], List[Optional[Point]]]

def simplpedpop_pre_finalize(state: SimplPedPopR1State,
                         vss_commitments_sum: VSSCommitmentSumExt, shares_sum: Scalar) \
                         -> Tuple[bytes, DKGOutput]:
    """
    Take the messages received from the coordinator and return eta to be compared and DKG output

    :param SimplPedPopR1State state: the signer's state output by simplpedpop_round1
    :param VSSCommitmentSumExt vss_commitments_sum: sum of VSS commitments received from the coordinator
    :param Scalar shares_sum: sum of shares for this participant received from all participants (including this participant)
    :return: the data `eta` that must be input to an equality check protocol, the final share, the shared pubkey, the individual participants' pubkeys
    """
    t, n, my_idx = state
    assert(len(vss_commitments_sum) == 2)
    assert(len(vss_commitments_sum[0]) == n + t - 1)
    assert(len(vss_commitments_sum[1]) == n)

    for i in range(n):
        P_i = vss_commitments_sum[0][i]
        if P_i is None:
            raise InvalidContributionError(i, "Participant sent invalid commitment")
        else:
            pk_i = xbytes(P_i)
            if not schnorr_verify(VSS_PoK_msg + i.to_bytes(4, byteorder="big"), pk_i, vss_commitments_sum[1][i]):
                raise InvalidContributionError(i, "Participant sent invalid proof-of-knowledge")
    # Strip the signatures and sum the commitments to the constant coefficients
    vss_commitment = vss_commitments_sum_finalize(vss_commitments_sum, t, n)
    if not vss_verify(my_idx, shares_sum, vss_commitment):
        raise VSSVerifyError()
    eta = t.to_bytes(4, byteorder="big") + serialize_vss_commitment(vss_commitment)
    shared_pubkey, signer_pubkeys = derive_group_info(vss_commitment, n, t)
    return eta, (shares_sum, shared_pubkey, signer_pubkeys)
```

### EncPedPop

EncPedPop is a thin wrapper around that SimplPedPop.
It takes care of encrypting the secret shares,
so that they can be sent over insecure channels.

EncPedPod encrypts the shares to a 33-byte public key
(as generated using [BIP 327's IndividualPubkey](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-generation-of-an-individual-signer) algorithm).

```python
def ecdh(deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    x = int_from_bytes(deckey)
    assert(x != 0)
    Y = cpoint(enckey)
    Z = point_mul(Y, x)
    assert Z is not None
    return int_from_bytes(tagged_hash_bip_dkg("ECDH", cbytes(Z) + context))

def encrypt(share: Scalar, my_deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    return (share + ecdh(my_deckey, enckey, context)) % GROUP_ORDER

def decrypt_sum(ciphertext_sum: Scalar, my_deckey: bytes, enckeys: List[bytes], my_idx: int, context: bytes) -> Scalar:
    shares_sum = ciphertext_sum
    for i in range(len(enckeys)):
        if i != my_idx:
            shares_sum = (shares_sum - ecdh(my_deckey, enckeys[i], context)) % GROUP_ORDER
    return shares_sum

EncPedPopR1State = Tuple[int, bytes, List[bytes], int, Scalar, SimplPedPopR1State]

def encpedpop_round1(seed: bytes, t: int, n: int, my_deckey: bytes, enckeys: List[bytes], my_idx: int) -> Tuple[EncPedPopR1State, VSSCommitmentExt, List[Scalar]]:
    assert(t < 2**(4*8))
    n = len(enckeys)

    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    enc_context = t.to_bytes(4, byteorder="big") + b''.join(enckeys)
    seed_ = tagged_hash_bip_dkg("EncPedPop seed", seed + enc_context)

    simpl_state, vss_commitment_ext, gen_shares = simplpedpop_round1(seed_, t, n, my_idx)
    assert(len(gen_shares) == n)
    enc_gen_shares : List[Scalar] = []
    for i in range(n):
        if i == my_idx:
            # TODO No need to send a constant.
            enc_gen_shares.append(0)
        else:
            try:
                enc_gen_shares.append(encrypt(gen_shares[i], my_deckey, enckeys[i], enc_context))
            except ValueError:  # Invalid enckeys[i]
                raise InvalidContributionError(i, "Participant sent invalid encryption key")
    self_share = gen_shares[my_idx]
    state1 = (t, my_deckey, enckeys, my_idx, self_share, simpl_state)
    return state1, vss_commitment_ext, enc_gen_shares

def encpedpop_pre_finalize(state1: EncPedPopR1State, vss_commitments_sum: VSSCommitmentSumExt, enc_shares_sum: Scalar) -> Tuple[bytes, DKGOutput]:
    t, my_deckey, enckeys, my_idx, self_share, simpl_state = state1
    n = len(enckeys)

    assert(len(vss_commitments_sum) == 2)
    assert(len(vss_commitments_sum[0]) == n + t - 1)
    assert(len(vss_commitments_sum[1]) == n)

    enc_context = t.to_bytes(4, byteorder="big") + b''.join(enckeys)
    shares_sum = decrypt_sum(enc_shares_sum, my_deckey, enckeys, my_idx, enc_context)
    shares_sum = (shares_sum + self_share) % GROUP_ORDER
    eta, dkg_output = simplpedpop_pre_finalize(simpl_state, vss_commitments_sum, shares_sum)
    eta += b''.join(enckeys)
    return eta, dkg_output
```

## ChillDKG

ChillDKG is a wrapper around EncPedPop which also includes the built-in equality check protocol `certifying_Eq`.
Its advantage is that recovering a signer is securely possible from a single seed and the full transcript of the protocol.
Since the transcript is public, every signer (and the coordinator) can store it to help recover any other signer.

For each signer, the DKG has three outputs: a secret share, the shared public key, and individual public keys for partial signature verification.
The secret share and shared public key are required by a signer to produce signatures and therefore, signers *must* ensure that they are not lost.

TODO: mention that these are properties when using the DKG with FROST
If a DKG session succeeds from the point of view of an honest signer by outputting a shared public key,
then unforgeability is guaranteed, i.e., no subset of `t-1` signers can create a signature.
TODO: Additionally, all honest signers receive correct DKG outputs, i.e., any set of t honest signers is able to create a signature.
TODO: consider mentioning ROAST


Generate long-term host keys.

```python
def chilldkg_hostkey_gen(seed: bytes) -> Tuple[bytes, bytes]:
    my_hostseckey = kdf(seed, "hostseckey")
    my_hostpubkey = pubkey_gen_plain(my_hostseckey)
    return (my_hostseckey, my_hostpubkey)
```

To initiate a concrete DKG session,
the participants send their host pubkey to all other participants and collect received host pubkeys.
We assume that the participants agree on the list of host pubkeys (including their order).
If they do not agree, the comparison of the session parameter identifier in the next protocol step will simply fail.
TODO: Params are the (ordered) list of host pubkeys (representing the signers) and threshold `t`.

They then compute a session parameter identifier that includes all participants (including yourself TODO: this is maybe obvious but probably good to stress, in particular for backups).

```python
SessionParams = Tuple[List[bytes], int, bytes]

def chilldkg_session_params(hostpubkeys: List[bytes], t: int, context_string: bytes) -> Tuple[SessionParams, bytes]:
    if len(hostpubkeys) != len(set(hostpubkeys)):
        raise DuplicateHostpubkeyError

    assert(t < 2**(4*8))
    params_id = tagged_hash("session parameters id", b''.join(hostpubkeys) + t.to_bytes(4, byteorder="big") + context_string)
    params = (hostpubkeys, t, params_id)
    return params, params_id
```

The participants compare the session parameters identifier with every other participant out-of-band.
If a participant is presented a session parameters identifier that does not match the locally computed session parameters identifier, the participant aborts.
Only if all other `n-1` session parameters identifiers are identical to the locally computed session parameters identifier, the participant proceeds with the protocol.

```python
ChillDKGStateR1 = Tuple[SessionParams, int, EncPedPopR1State]

def chilldkg_round1(seed: bytes, params: SessionParams) -> Tuple[ChillDKGStateR1, VSSCommitmentExt, List[Scalar]]:
    my_hostseckey, my_hostpubkey = chilldkg_hostkey_gen(seed)
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)

    my_idx = hostpubkeys.index(my_hostpubkey)
    enc_state1, vss_commitment_ext, enc_gen_shares = encpedpop_round1(seed, t, n, my_hostseckey, hostpubkeys, my_idx)
    state1 = (params, my_idx, enc_state1)
    return state1, vss_commitment_ext, enc_gen_shares
```

```python
ChillDKGStateR2 = Tuple[SessionParams, bytes, DKGOutput]

def chilldkg_round2(seed: bytes, state1: ChillDKGStateR1, vss_commitments_sum: VSSCommitmentSumExt, all_enc_shares_sum: List[Scalar]) -> Tuple[ChillDKGStateR2, bytes]:
    (my_hostseckey, _) = chilldkg_hostkey_gen(seed)
    (params, my_idx, enc_state1) = state1

    # TODO Not sure if we need to include params_id as eta here. But it won't hurt.
    # Include the enc_shares in eta to ensure that participants agree on all
    # shares, which in turn ensures that they have the right backup.
    # TODO This means all parties who hold the "backup" in the end should
    # participate in Eq?
    my_enc_share = all_enc_shares_sum[my_idx]

    eta, dkg_output = encpedpop_pre_finalize(enc_state1, vss_commitments_sum, my_enc_share)
    eta += b''.join([bytes_from_int(share) for share in all_enc_shares_sum])
    state2 = (params, eta, dkg_output)
    return state2, certifying_eq_round1(my_hostseckey, eta)

def chilldkg_finalize(state2: ChillDKGStateR2, cert: bytes) -> Union[DKGOutput, Literal[False]]:
    """
    A return value of False means that `cert` is not a valid certificate.

    You MUST NOT delete `state2` in this case.
    The reason is that some other participant may have a valid certificate and thus deem the DKG session successful.
    That other participant will rely on us not having deleted `state2`.
    Once you obtain that valid certificate, you can call `chilldkg_finalize` again with that certificate.
    """
    (params, eta, dkg_output) = state2
    hostpubkeys = params[0]
    if not certifying_eq_finalize(hostpubkeys, eta, cert):
        return False
    return dkg_output
```

```python
def chilldkg_backup(state2: ChillDKGStateR2, cert: bytes) -> Any:
    eta = state2[1]
    return (eta, cert)

async def chilldkg(chan: SignerChannel, seed: bytes, my_hostseckey: bytes, params: SessionParams) -> Union[Tuple[DKGOutput, Any], Literal[False]]:
    state1, vss_commitment_ext, enc_gen_shares = chilldkg_round1(seed, params)
    chan.send((vss_commitment_ext, enc_gen_shares))
    vss_commitments_sum, all_enc_shares_sum = await chan.receive()

    try:
        state2, eq_round1 = chilldkg_round2(seed, state1, vss_commitments_sum, all_enc_shares_sum)
    except Exception as e:
        print("Exception", repr(e))
        return False

    chan.send(eq_round1)
    cert = await chan.receive()
    dkg_output = chilldkg_finalize(state2, cert)
    if dkg_output == False:
        return False

    return (dkg_output, chilldkg_backup(state2, cert))
```

#### Certifying equality check protocol based on Goldwasser-Lindell Echo Broadcast

The equality check of ChillDKG is instantiated by the following protocol:

```python
def certifying_eq_round1(my_hostseckey: bytes, x: bytes) -> bytes:
    # TODO: fix aux_rand
    return schnorr_sign(x, my_hostseckey, b'0'*32)

def verify_cert(hostpubkeys: List[bytes], x: bytes, cert: bytes) -> bool:
    n = len(hostpubkeys)
    if len(cert) != 64*n:
        return False
    is_valid = [schnorr_verify(x, hostpubkeys[i][1:33], cert[i*64:(i+1)*64]) for i in range(n)]
    return all(is_valid)

def certifying_eq_finalize(hostpubkeys: List[bytes], x: bytes, cert: bytes) -> bool:
    return verify_cert(hostpubkeys, x, cert)

async def certifying_eq_coordinate(chans: CoordinatorChannels, hostpubkeys: List[bytes]) -> bytes:
    n = len(hostpubkeys)
    sigs = []
    for i in range(n):
        sig = await chans.receive_from(i)
        sigs += [sig]
    cert = b''.join(sigs)
    chans.send_all(cert)
    return cert
```

#### Coordinator

```python
def serialize_eta(t: int, vss_commit: VSSCommitment, hostpubkeys: List[bytes], all_enc_shares_sum: List[Scalar]) -> bytes:
    return (t.to_bytes(4, byteorder="big")
            + serialize_vss_commitment(vss_commit)
            + b''.join(hostpubkeys)
            + b''.join([bytes_from_int(share) for share in all_enc_shares_sum]))

async def chilldkg_coordinate(chans: CoordinatorChannels, params: SessionParams) -> Union[GroupInfo, Literal[False]]:
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)
    vss_commitments_ext = []
    all_enc_shares_sum = [0]*n
    for i in range(n):
        vss_commitment_ext, enc_shares = await chans.receive_from(i)
        vss_commitments_ext += [vss_commitment_ext]
        all_enc_shares_sum = [ scalar_add(all_enc_shares_sum[j], enc_shares[j]) for j in range(n) ]
    vss_commitments_sum = vss_sum_commitments(vss_commitments_ext, t)
    chans.send_all((vss_commitments_sum, all_enc_shares_sum))
    eta = serialize_eta(t, vss_commitments_sum_finalize(vss_commitments_sum, t, n), hostpubkeys, all_enc_shares_sum)
    cert = await certifying_eq_coordinate(chans, hostpubkeys)
    if not verify_cert(hostpubkeys, eta, cert):
        return False
    vss_commitment = vss_commitments_sum_finalize(vss_commitments_sum, t, n)
    return derive_group_info(vss_commitment, n, t)
```

![chilldkg diagram](images/chilldkg-sequence.png)

#### Backup and Recovery
Losing the secret share or the shared public key will render the signer incapable of participating in signing sessions.
As these values depend on the contributions of the other signers to the DKG, they can, unlike secret keys in BIP 340 or BIP 327, not be derived solely from the signer's seed.

To facilitate backups of a DKG session,
ChillDKG offers the possibility to recover a signer's outputs of the session from the signer's seed and the DKG transcript of the specific session.
As a result, a full backup of a signer consists of the seed and the transcripts of all DKGs sessions the signer has participated in.
(TODO Which sessions? Probably all sessions deemed successful, i.e., the backup should be exported as part of `finalize`.)
Since the transcript is verifiable and the same for all signers,
if a signer loses the backup of the transcript of the DKG session,
they can request it from any other signers.
Moreover, since the transcript contains secret shares only in encrypted form,
it can in principle be stored with a third-party backup provider.
(TODO: But there are privacy implications. The hostpubkeys and shared public key can be inferred from the transcript. We could encrypt the full transcript to everyone... We'd only need to encrypt a symmetric key to everyone.)

Note that it may not be an unreasonable strategy in a threshold setup not to perform backups of signers at all,
and simply hope that `t` honest and working signers will remain available.
As soon as one or more signers are lost or broken, new DKG session can be performed with the unavailable signers replaced.
One drawback of this method is that it will result in a change of the shared public key,
and the application will, therefore, need to transition to the new shared public key
(e.g., funds stored under the current shared public key need to be transferred to the new key).

Whether to perform backups and how to manage them ultimately depends on the requirements of the application,
and we believe that a general recommendation is not useful.

```python
def deserialize_eta(b: bytes) -> Any:
    # eta = t (4) + vss_commit (33*t) + enckeys (33*n) + enc_shares (32*n)
    rest = b

    assert(len(rest) >= 4)
    t, rest = int.from_bytes(rest[:4], byteorder="big"), rest[4:]

    assert(len(rest) >= 33*t)
    vss_commit, rest = deserialize_vss_commitment(rest[:33*t], t), rest[33*t:]

    n, remainder = divmod(len(rest), (33 + 32))
    assert(remainder == 0)

    assert(len(rest) >= 33*n)
    hostpubkeys, rest = [rest[i:i+33] for i in range(0, 33*n, 33)], rest[33*n:]

    assert(len(rest) >= 32*n)
    all_enc_shares_sum, rest = [int_from_bytes(rest[i:i+32]) for i in range(0, 32*n, 32)], rest[32*n:]

    assert(len(rest) == 0)
    return (t, vss_commit, hostpubkeys, all_enc_shares_sum)

# Recovery requires the seed and the public backup
def chilldkg_recover(seed: bytes, backup: Any, context_string: bytes) -> Union[Tuple[DKGOutput, SessionParams], Literal[False]]:
    (eta, cert) = backup
    # TODO: deserialize_eta can fail
    (t, vss_commit, hostpubkeys, all_enc_shares_sum) = deserialize_eta(eta)
    (params, params_id) = chilldkg_session_params(hostpubkeys, t, context_string)
    my_hostseckey, my_hostpubkey = chilldkg_hostkey_gen(seed)

    # Verify cert
    verify_cert(hostpubkeys, eta, cert)
    # Decrypt share
    enc_context = t.to_bytes(4, byteorder="big") + b''.join(hostpubkeys)
    # TODO: this may fail
    my_idx = hostpubkeys.index(my_hostpubkey)
    shares_sum = decrypt_sum(all_enc_shares_sum[my_idx], my_hostseckey, hostpubkeys, my_idx, enc_context)
    # TODO: don't call full round1 function
    (state1, _, _) = encpedpop_round1(seed, t, len(hostpubkeys), my_hostseckey, hostpubkeys, my_idx)
    self_share = state1[4]
    shares_sum = (shares_sum + self_share) % GROUP_ORDER

    # Compute shared & individual pubkeys
    (shared_pubkey, signer_pubkeys) = derive_group_info(vss_commit, len(hostpubkeys), t)
    dkg_output = (shares_sum, shared_pubkey, signer_pubkeys)

    return dkg_output, params
```

TODO: make the following a footnote
There are strategies to recover if the backup is lost and other signers assist in recovering.
In such cases, the recovering signer must be very careful to obtain the correct secret share and shared public key!
1. If all other signers are cooperative and their seed is backed up (EncPedPop or ChillDKG), it's possible that the other signers can recreate the signer's lost secret share.
2. If threshold-many signers are cooperative, they can use the "Enrolment Repairable Threshold Scheme" described in [these slides](https://github.com/chelseakomlo/talks/blob/master/2019-combinatorial-schemes/A_Survey_and_Refinement_of_Repairable_Threshold_Schemes.pdf).
   This scheme requires no additional backup or storage space for the signers.
These strategies are out of scope for this document.

## Background on Equality Check Protocols

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

The [equality check protocol used by ChillDKG](#certifying-equality-check-protocol-based-on-goldwasser-lindell-echo-broadcast) is applicable to network-based scenarios where long-term host keys are available. It satisfies integrity and conditional agreement.

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
