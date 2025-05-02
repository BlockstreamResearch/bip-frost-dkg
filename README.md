```
BIP:
Title: ChillDKG: Distributed Key Generation for FROST
Author: Tim Ruffing <crypto@timruffing.de>
        Jonas Nick <jonas@n-ck.net>
Status: Draft
License: CC0-1.0
License-Code: MIT
Type: Informational
Created:
Post-History:
Comments-URI:
```

# ChillDKG: Distributed Key Generation for FROST

### Abstract

This Bitcoin Improvement Proposal proposes ChillDKG, a distributed key generation protocol (DKG) for use with the FROST Schnorr threshold signature scheme.

### Copyright

This document is made available under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
The accompanying source code is licensed under the [MIT license](https://opensource.org/license/mit).

## Introduction

### Motivation

The FROST signature scheme [[KG20](https://eprint.iacr.org/2020/852), [CKM21](https://eprint.iacr.org/2021/1375), [BTZ21](https://eprint.iacr.org/2022/833), [CGRS23](https://eprint.iacr.org/2023/899)] enables `t`-of-`n` Schnorr threshold signatures,
in which some threshold `t` of a group of `n` participants is required to produce a signature.
FROST remains unforgeable as long as at most `t-1` participants are compromised
and remain functional as long as `t` honest participants do not lose their secret key material.
Notably, FROST can be made compatible with [BIP 340](bip-0340.mediawiki) Schnorr signatures and does not put any restrictions on the choice of `t` and `n` (as long as `1 <= t <= n`).[^t-edge-cases]

[^t-edge-cases]: While `t = n` and `t = 1` are in principle supported, simpler alternatives are available in these cases.
In the case of `t = n`, using a dedicated `n`-of-`n` multi-signature scheme such as MuSig2 [[BIP 327](bip-0327.mediawiki)] instead of FROST avoids the need for an interactive DKG.
The case `t = 1` can be realized by letting one participant generate an ordinary [BIP 340](bip-0340.mediawiki) key pair and transmitting the key pair to every other participant, who can check its consistency and then simply use the ordinary [BIP 340](bip-0340.mediawiki) signing algorithm.
Participants still need to ensure that they agree on a key pair. A detailed specification is not in the scope of this document.

As a result, threshold signatures increase both security and availability,
enabling users to escape the inherent dilemma between the contradicting goals of protecting a single secret key against theft and data loss simultaneously.
Before being able to create signatures, the participants need to generate a shared *threshold public key* (representing the entire group with its `t`-of-`n` policy),
together with `n` corresponding *secret shares* (held by the `n` participants) that allow to sign under the threshold public key.
This key generation can, in principle, be performed by a trusted dealer who takes care of generating the threshold public key as well as all `n` secret shares,
which are then distributed to the `n` participants via secure channels.
However, the trusted dealer constitutes a single point of failure:
a compromised dealer can forge signatures arbitrarily.

An interactive *distributed key generation* (DKG) protocol session by all participants avoids the need for a trusted dealer.
There exist a number of DKG protocols with different requirements and guarantees in the cryptographic literature.
Most suitable for the use with FROST is the PedPop DKG protocol [[KG20](https://eprint.iacr.org/2020/852), [CKM21](https://eprint.iacr.org/2021/1375), [CGRS23](https://eprint.iacr.org/2023/899)] ("Pedersen DKG [[Ped92](https://doi.org/10.1007/3-540-46766-1_9), [GJKR07](https://doi.org/10.1007/s00145-006-0347-3)] with proofs of possession"),
which, like FROST, does not impose restrictions on the choice of `t` and `n`.

But similar to most DKG protocols in the literature, PedPop has strong requirements on the communication channels between participants,
which make it difficult to deploy in practice:
First, it assumes that participants have secure (i.e., authenticated and encrypted) channels between each other,
which is necessary to avoid man-in-the-middle attacks and to ensure confidentiality of secret shares when delivering them to individual participants.
Second, PedPop assumes that all participants have access to some external consensus or reliable broadcast mechanism
that ensures they have an identical view of the protocol messages exchanged during DKG.
This will, in turn, ensure that all participants eventually reach agreement over the results of the DKG,
which include not only parameters such as the generated threshold public key
but also whether the DKG has succeeded at all.

To understand the necessity of reaching agreement,
consider the example of a DKG to set up a 2-of-3 Bitcoin wallet
in which two participants are honest but the third participant is malicious.
The malicious participant sends invalid secret shares to the first honest participant, but valid shares to the second honest participant.
While the first honest participant cannot finish the DKG,
the second honest participant will believe that the DKG has finished successfully
and thus may be willing to send funds to the resulting threshold public key.
But this constitutes a catastrophic failure:
Those funds will be lost irrevocably because the single remaining secret share of the second participant will not be sufficient to produce a signature (without the help of the malicious participant).[^resharing-attack]

[^resharing-attack]: A very similar attack has been observed in the implementation of a resharing scheme [[AS20](https://eprint.iacr.org/2020/1052), Section 3].

To sum up, there is currently no description of PedPop that
does not assume the availability of external secure channels and consensus
and thus can be turned into a standalone implementation.
To overcome these issues, we propose ChillDKG in this BIP.
ChillDKG is a variant of PedPop with "batteries included",
i.e., it incorporates minimal but sufficient implementations of secure channels and consensus
and thus does not have external dependencies.
This makes it easy to implement and deploy, and
we provide detailed algorithmic specifications in the form of Python code.

### Design

We assume a network setup in which participants have point-to-point connections to an untrusted coordinator.
This will enable bandwidth optimizations and is common also in implementations of the signing stage of FROST.
Participants are identified and authenticated via long-term public keys.

The basic building block of ChillDKG is the SimplPedPop protocol (a simplified variant of PedPop),
which has been designed specifically for FROST.
SimplPedPop is proven to be secure when combined with FROST [[CGRS23](https://eprint.iacr.org/2023/899)],
and its output contains, in addition to the threshold public key, separate per-participant public shares thereof,
which allow for partial verification of contributions in a FROST signing session.

Besides external secure channels, SimplPedPop depends on an external *equality check protocol*.
The equality check protocol serves as an abstraction of a consensus mechanism:
Its only purpose is to check that, at the end of SimplPedPop, all participants have received identical protocol messages.

Our goal is to turn SimplPedPop into a standalone DKG protocol without external dependencies.
We then follow a modular approach that removes one dependency at a time.
First, we take care of secure channels by wrapping SimplPedPop in a protocol EncPedPop,
which relies on pairwise ECDH key exchanges between the participants to encrypt secret shares.
Finally, we add a concrete equality check protocol CertEq to EncPedPop to obtain a standalone DKG protocol ChillDKG.

Our equality check protocol CertEq consists of every participant simply collecting a list of valid signatures on the session transcript from all `n` participants
before finalizing the DKG session with some threshold public key as output.
The list of signatures, also called a *success certificate*, can convince any other honest participant
(ultimately at the time of a signing request)
that the DKG session has indeed been successful.
This is sufficient to exclude the catastrophic failure described in the previous section.

As an additional feature of ChillDKG, the DKG outputs for any signing device can be fully recovered from
a backup of a single *host secret key* specific to the device,
(the essential parts of) the public transcripts of the DKG sessions,
and the corresponding success certificates.
To simplify the interface, we combine the transcript data and the session certificate into a single byte string called the *recovery data*,
which is common to all participants and does not need to be kept confidential.
Recovering a device that has participated in a DKG session then requires just the device's host secret key and the recovery data,
the latter of which can be obtained from any cooperative participant (or the coordinator) or from an untrusted backup provider.

ChillDKG outputs a threshold public key that can be safely used in Taproot outputs [[BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)].
In contrast, a standard PedPop implementation would allow a malicious participant to secretly embed a Taproot commitment to a script path within the threshold public key.
If such a key was used directly in a Taproot output, the malicious participant could spend the output through their hidden script path, bypassing the requirement for `t - 1` additional signatures.
While [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) outlines special precautions for using threshold public keys generated by standard PedPop, ChillDKG eliminates this vulnerability entirely, providing built-in protection against accidental misuse.

If a ChillDKG session fails due to the participants or the coordinator deviating from the protocol,
any aborting party will be able to identify and blame a single party responsible for the failure
(assuming the network, and, depending on the circumstances, the coordinator, is reliable).

These features make ChillDKG usable in a wide range of applications.
As a consequence of this broad applicability, there will necessarily be scenarios in which specialized protocols need less communication overhead and fewer rounds,
e.g., when setting up multiple signing devices in a single location.

In summary, we aim for the following design goals:

 - **Standalone**: ChillDKG is fully specified, requiring no external secure channels or consensus mechanism.
 - **Conditional agreement**: If a ChillDKG session succeeds for one honest participant, this participant will be able to convince every other honest participant that the session has succeeded.
 - **No restriction on threshold**:  Like the FROST signing protocol, ChillDKG supports any threshold `t <= n`, including `t > n/2` (also called "dishonest majority").
 - **Broad applicability**:  ChillDKG supports a wide range of scenarios, from those where the signing devices are owned and connected by a single individual to those where multiple owners manage the devices from distinct locations.
 - **Simple backups**: ChillDKG allows recovering the DKG output using the host secret key and common recovery data shared among all participants and the coordinator. This eliminates the need for session-specific backups, simplifying user experience.
 - **Untrusted coordinator**: Like FROST, ChillDKG uses a coordinator that relays messages between the participants. This simplifies the network topology, and the coordinator additionally reduces communication overhead by aggregating some of the messages. A faulty coordinator can force the DKG to fail but cannot negatively affect the security of the DKG.
 - **Per-participant public shares**: ChillDKG supports partial signature verification in FROST signing sessions.
 - **Taproot-safe threshold public key**: ChillDKG prevents malicious participants from embedding a hidden Taproot commitment to a script path in the threshold public key.
 - **Blame functionality**: If a ChillDKG session aborts, it is possible to identify and blame a single party responsible for the failure (assuming the network, and, depending on the circumstances, the coordinator, is reliable).

In summary, ChillDKG incorporates solutions for both secure channels and consensus and simplifies backups in practice.
As a result, it fits a wide range of application scenarios,
and due to its low overhead, we recommend ChillDKG even if secure communication channels or a consensus mechanism (e.g., a BFT protocol or a reliable broadcast mechanism) are readily available.

#### Why Robustness is Not a Goal

Despite the blame functionality, ChillDKG does not provide robustness, i.e., the protocol is not designed to succeed in the presence of faulty participants.
In fact, a single participant can cause the protocol to fail, either due to malicious intent, software bugs, or unreliable communication links.
In such cases, users must investigate and resolve the issue before the DKG can output key material.

Adding robustness to ChillDKG would require the coordinator to exclude participants that appear unresponsive or faulty, which degrades the setup already from the beginning from `t`-of-`n` to `(t-1)`-of-`(n-1)`.
This approach is undesirable in most scenarios, as a faulty coordinator would have the power to exclude participants at will,
and even if ChillDKG's design did not include a coordinator and participants had direct communication links to each other, it would be unclear how to achieve robustness in a dishonest majority setting.

Moreover, we believe that it is preferable to err on the side of caution even in the case of benign failures.
For example, consider a key generation ceremony for a threshold cold wallet intended to store large amounts of Bitcoin.
If it turns out that one of the devices participating appears non-responsive, e.g., due to a loss of network or a software bug,
users will typically prefer security to progress, and abort the protocol instead of forcing successful termination of the ceremony by excluding the device from the DKG session.
While warnings can be presented to users in this case, users tend to misunderstand and ignore them.

Even in distributed systems with strict liveness requirements, e.g., a system run by a large federation of nodes of which a majority is trusted, what is typically necessary for the liveness of the system is the continued ability to *produce signatures*.
However, the setup of keys is typically performed in a one-time ceremony at the inception of the system (and possibly repeated in large time intervals, e.g., every few months).
In other words, what is primarily required to ensure liveness in these applications is a robust signing protocol
(and a solution for FROST exists [[RRJSS22](https://eprint.iacr.org/2022/550)]), and not a robust DKG protocol.

### Structure of this Document

Due to the complexity of ChillDKG, we do not provide both a pseudocode specification and a reference implementation.
Instead, the BIP includes only a normative reference implementation in Python 3.12
(see [`python/chilldkg_ref/chilldkg.py`](python/chilldkg_ref/chilldkg.py)),
which serves as an executable specification.

To ease understanding of the design and reference code,
we provide a technical overview of the internals of ChillDKG in [Section "Internals of ChillDKG"](#internals-of-chilldkg).
For those who would like to use a ChillDKG implementation in their applications and systems,
we explain the external interface and usage considerations of ChillDKG in [Section "Usage of ChillDKG"](#usage-of-chilldkg).

## Internals of ChillDKG

This section provides a detailed technical overview of the internals of ChillDKG,
which includes as building blocks the DKG protocols SimplPedPop and EncPedPop, and the equality check protocol CertEq.
The contents of this section are purely informational and not strictly required to implement or use ChillDKG,
and some details present in the normative Python reference implementation are omitted.

We stress that **this document does not endorse the direct use of SimplPedPop or EncPedPop as DKG protocols**.
While SimplPedPop and EncPedPop may in principle serve as building blocks of other DKG protocols (e.g., for applications that already incorporate a consensus mechanism),
this requires careful further consideration, which is not in the scope of this document.
Consequently, implementations should not expose the algorithms of the building blocks as part of a high-level API, which is intended to be safe to use.

### DKG Protocol SimplPedPop

(See [`python/chilldkg_ref/simplpedpop.py`](python/chilldkg_ref/simplpedpop.py).)

The SimplPedPop protocol has been proposed by Chu, Gerhart, Ruffing, and Schröder [Section 4, [CGRS23](https://eprint.iacr.org/2023/899)].
We make the following modifications as compared to the original SimplPedPop proposal:

 - Every participant holds a secret seed, from which all required random values are derived deterministically using a pseudorandom function (based on tagged hashes [[BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)]).
 - Individual participants' public shares are added to the output of the DKG. This allows partial signature verification.
 - The participants send VSS commitments to an untrusted coordinator instead of directly to each other. This lets the coordinator aggregate VSS commitments, which reduces communication costs. Nevertheless, if a session fails, participants are able to investigate who provided invalid secret shares by asking the coordinator for the other participants' individual contributions to their public share.
 - To prevent a malicious participant from embedding a Taproot script path in the threshold public key, the participants tweak the VSS commitment such that the corresponding threshold public key has an unspendable script path.
 - ~The proofs of knowledge are not included in the data for the equality check. This will reduce the size of the backups in ChillDKG.~ (TODO: This will be fixed in an updated version of the paper.)

Our variant of the SimplPedPop protocol then works as follows:

1.  Every participant `i` (where `i` is an integer `0 <= i < n`) creates a `t`-of-`n` sharing of a random secret scalar using Feldman Verifiable Secret Sharing (VSS), a variant of Shamir Secret Sharing.
    This involves generating random coefficients `a_i[0], ..., a_i[t-1]` of a polynomial `f_i` of degree `t-1` in the scalar group:

    ```
    f_i(Z) = a_i[0] + a_i[1] * Z + ... a_i[t-1] * Z^(t-1)
    ```

    Here, `f_i(0) = a_i[0]` acts as the secret scalar to be shared.
    Participant `i` computes a VSS share `shares[j] = f_i(j+1)` for every participant `j` (including `j = i`),
    which is supposed to be sent to participant `j` in private.
    (This will be realized in EncPedPop using encryption.)

    Participant `i` then sends a VSS commitment,
    which is a vector `com = (com[0], ...,  com[t-1]) = (a_i[0] * G, ...,  a_i[t-1] * G)` of group elements,
    where `G` is the base point of the secp256k1 elliptic curve,
    and a BIP 340 Schnorr signature `pop` on message "`i`" with secret key `a_i[0]` to the coordinator.
    (The Schnorr signature acts as a *proof of possession*,
    i.e., it proves knowledge of the discrete logarithm of `com[0] = a_i[0] * G`.
    This avoids rogue-key attacks, also known as key cancellation attacks.)

2.  Upon receiving `coms[j] = (coms[j][0], ...,  coms[j][t-1])` and `pops[j]` from every participant `j`,
    the coordinator aggregates the commitments
    by computing the component-wise sum of all `coms[j]` vectors except for their first components `coms[j][0]`,
    which are simply concatenated (because the participants will need them to verify the proofs of possession):

    ```
    sum_coms_to_nonconst_terms = (coms[0][1] + ... + coms[n-1][1], ..., coms[0][t-1] + ... + coms[n-1][t-1])
    coms_to_secrets = (coms[0][0], ..., coms[n-1][0])
    ```

    The coordinator sends the vectors `coms_to_secrets`, `sum_coms_to_nonconst_terms`, and `pops` to every participant.

3.  Upon receiving `coms_to_secrets`, `sum_coms_to_nonconst_terms`, and `pops` from the coordinator,
    every participant `i` verifies every signature `pops[j]` using message `j` and public key `coms_to_secrets[j]`.
    If any signature, say the one from participant `j`, is invalid, participant `i` aborts and blames participant `j` for the failure of the session.

    Otherwise, i.e., if all signatures are valid, participant `i` sums the components of `coms_to_secrets`,
    and prepends the sum to the `sum_coms_to_nonconst_terms` vector, resulting in a vector `sum_coms`.
    (Assuming the coordinator performed its computations correctly,
    the vector `sum_coms` is now the complete component-wise sum of the `coms[j]` vectors from every participant `j`.
    It acts as a VSS commitment to the sum `f = f_0 + ... + f_{n-1}` of the polynomials of all participants.)

    Participant `i` computes its public share `pubshare` as:
    ```
    pubshare = (i+1)^0 * sum_coms[0] + ... + (i+1)^(t-1) * sum_coms[t-1]
    ```

    Let `partial_secshares` be the vector of the VSS shares that participant `i` has privately obtained from each participant,
    and let `secshare = partial_secshares[0] + ... + partial_secshares[n-1]` be the sum of the vector components.
    Participant `i` checks the validity of `secshare` against `sum_coms`
    by checking if the equation `secshare * G = pubshare` holds.
    (`secshare` is supposed to be equal to `f(i+1)`.)

    If the check fails, participant `i` aborts.
    Assuming the coordinator is honest and has sent a correct `sums_coms` vector,
    participant `i` knows that some participant contributed a wrong summand to `secshare`,
    but participant `i` does not have sufficient information to single out and blame the faulty participant.
    In this case, participant `i` can optionally investigate the error by asking the coordinator for the vector `partial_pubshares` defined as:
    ```
    partial_pubshares[j] = (i+1)^0 * coms[j][0] + ... + (i+1)^(t-1) * coms[j][t-1]
    ```
    With this vector at hand, participant `i` verifies each component of `partial_secshares` individually
    by checking for which participant `j` the equation `partial_secshares[j] * G = partial_pubshares[j]` does not hold.
    Participant `i` blames this participant `j` .

    Otherwise, i.e., in the successful case that the equation `secshare * G = pubshare` holds, participant `i` proceeds as follows.
    In order to obtain a threshold public key with an unspendable Taproot script path [[BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)],
    participant `i` computes a Taproot tweak `tweak` for an unspendable script path,
    and adds the point `tweak * G` to `sum_coms[0]`, resulting in a new VSS commitment called `sum_coms_tweaked`.
    Participant `i` computes the public share of every participant as
    ```
    pubshares[j] = (j+1)^0 * sum_coms_tweaked[0] + ... + (j+1)^(t-1) * sum_coms_tweaked[t-1]
    ```
    Correspondingly, participant `i` computes `secshare_tweaked = secshare + tweak`.

    Then, participant `i` sets the DKG output consisting of
    this participant's secret share `secshare_tweaked`,
    the threshold public key `threshold_pubkey = sum_coms_tweaked[0]`, and
    all participants' public shares `pubshares`.

    As a final step, participant `i` enters a session of an external equality check protocol
    to verify that all participants agree on the *transcript*, i.e., common data produced during the session,
    and that none of them has aborted the session due to an invalid VSS share or an invalid proof of possession.
    The transcript of SimplPedPop, constructed in a variable `eq_input`,
    is simply the concatenation (of serializations) of `t` and the `sum_coms` vector.
    Upon the equality protocol returning successfully,
    participant `i` returns successfully with the DKG outputs as computed above.
    Details of the interface of the equality check protocol will be described further below in
    [Subsection "Background on Equality Checks"](#background-on-equality-checks).

### DKG Protocol EncPedPop

(See [`python/chilldkg_ref/encpedpop.py`](python/chilldkg_ref/encpedpop.py).)

EncPedPop is a thin wrapper around SimplPedPop that takes care of encrypting the VSS shares
so that they can be sent over an insecure communication channel.

As in SimplPedPop, every EncPedPop participant holds a long-term secret seed.
Every participant derives from this seed a static, long-term ECDH key pair consisting of a secret decryption key and a public encryption key.
It is assumed that every participant has an authentic copy of every other participant's encryption key.

The encryption relies on ephemeral-static ECDH key exchange.
Every participant derives from fresh randomness an ephemeral encryption nonce pair consisting of a secret nonce and the corresponding public nonce.
This will enable every pair of sending participant `i` and recipient participant `j != i`
to perform an ECDH key exchange between the ephemeral encryption nonce pair of participant `i` and the static encryption key pair of participant `j`
in order to establish a shared secret pad `pad_ij` only known to participants `i` and `j`.
The derivation of `pad_ij` from the raw ECDH output uses a tagged hash and includes
additional context, namely the static encryption key and the index `j` of the recipient.[^mr-kem]

[^mr-kem]: This implements a multi-recipient multi-key key encapsulation mechanism (MR-MK-KEM) secure under the static Diffie-Hellman assumption [[Theorem 2, PPS14](https://doi.org/10.1145/2590296.2590329)].

When `j = i` (i.e., when a participant encrypts a VSS share for themselves), the computationally expensive ECDH key exchange is unnecessary.
Instead, the participant repurposes the secret decryption key as a symmetric key, such that `pad_ii` is computed as the tagged hash of the decryption key, public encryption nonce, and context.

Every participant derives an ephemeral *session seed* passed down to SimplPedPop from their long-term seed and their public encryption nonce.
Moreover, all encryption keys of all participants are included in the derivation to ensure that different sets of participants will have different SimplPedPop sessions,
even in the case that the randomness for deriving the encryption nonce pair is accidentally reused.

EncPedPop then works like SimplPedPop with the following differences:
Participant `i` will additionally transmit their public encryption nonce and an encrypted VSS share `shares[j] + pad_ij` for every other participant `j`
as part of the first message to the coordinator.
The coordinator collects all encrypted VSS shares,
and computes the sum `enc_secshare[i]` of all shares intended for every participant `i`.
The coordinator sends all public encryption nonces along with the sum `enc_secshare[i]` to participant `i`.
Participant `i` stores the sum as `enc_secshare`,
derives the pads `pad_0i`, ..., `pad_ni` as described above,
obtains the value `secshare = enc_secshare - (pad_0i + ... + pad_ni)`,
and passes it down to SimplPedPop.

If SimplPedPop raises an error because this `secshare` value fails VSS verification,
then participant `i` can optionally investigate the error
by asking the coordinator for the vector `enc_partial_secshares` of the individual contributions of all participants to `enc_secshare`.
Participant `i` obtains the vector `partial_secshares`, which SimplPedPop requires for investigating the error,
by decrypting the components of `enc_partial_secshares` via `partial_secshares[j] = enc_partial_secshares[j] - pad_ji` for every other participant `j`.
Then, participant `i` can pass `partial_secshares` down to SimplPedPop,
which, after additionally obtaining the vector `partial_pubshares` from the coordinator,
has all the information required to determine and blame a faulty participant.

Otherwise, i.e., if SimplPedPop does not raise an error,
EncPedPop appends to the transcript `eq_input` of SimplPedPop the `n` public encryption nonces,
and also all the `n` static encryption keys to ensure that the participants agree on their identities.
The inclusion of the latter excludes man-in-the-middle attacks if Eq authenticates participants,
e.g, if the Eq protocol messages are signed under long-term public keys of the participants.

### Background on Equality Checks

As explained in the "Motivation" section, it is crucial for security that participants reach agreement over the results of a DKG session.
SimplPedPop, and consequently also EncPedPop, ensure agreement during the final step of the DKG session by running an external *equality check protocol* Eq.
The purpose of Eq is to verify that all participants have received an identical *transcript*, which is a byte string constructed by the respective DKG protocol.

Eq is assumed to be an interactive protocol between the `n` participants with the following abstract interface:
Every participant can invoke a session of Eq with an input value `eq_input`.
Eq may not return at all to the calling participant,
but if it returns successfully to some participant, then all honest participants agree on the value `eq_input`.
(However, it may be the case that not all honest participants have established this fact yet.)
This means that the DKG session was successful, and the resulting threshold public key can be returned to the participant,
who can use it, e.g., by sending funds to some Bitcoin address derived from it.

More formally, Eq must fulfill the following properties [[CGRS23](https://eprint.iacr.org/2023/899)]:
 - **Integrity:** If Eq returns successfully to some honest participant, then for every pair of input values `eq_input` and `eq_input'` provided by two honest participants, we have `eq_input = eq_input'`.
 - **Conditional Agreement:** Assuming all messages are delivered eventually, if Eq returns successfully to some honest participant, then Eq will eventually return successfully to all honest participants.

Depending on the application scenario, different approaches may be suitable to implement Eq,
such as a consensus protocol already available as part of a federated system
or out-of-band communication.
For example, in a scenario where a single user employs multiple signing devices to set up a threshold wallet,
every device could display its value `eq_input` (or a hash of `eq_input` under a collision-resistant hash function) to the user.
The user could manually verify the equality of the values by comparing the values shown on all displays,
and confirm their equality by providing explicit confirmation to every device, e.g., by pressing a button on every device.
Similarly, if signing devices are controlled by different organizations in different geographic locations,
agents of these organizations could meet and compare the values.
A detailed treatment of these out-of-band methods is out of scope of this document.

### DKG Protocol ChillDKG

(See [`python/chilldkg_ref/chilldkg.py`](python/chilldkg_ref/chilldkg.py).)

Instead of performing an out-of-band check as the last step of the DKG,
ChillDKG relies on a more direct approach:
It is a wrapper around EncPedPop,
which instantiates the required equality check protocol with a concrete in-band protocol CertEq.
CertEq assumes that each participant holds a long-term key pair of a signature scheme, called the *host key pair*.
ChillDKG repurposes the host key pairs as the ECDH key pairs required by EncPedPop,[^joint-security]
and it repurposes the host secret key as the seed required by EncPedPop.

[^joint-security]: Schnorr signatures and ECDH-based KEMs are known to be jointly secure [Theorem 2, [DLPSS11](https://eprint.iacr.org/2011/615)]
under the combination of the gap-DH and gap-DL assumptions, and this result can be adapted to the MR-KEM used in EncPedPop.

ChillDKG requires that all participants have authentic copies of the other participants' host public keys.[^trust-anchor]
Authenticity of the host public keys can be verified through pairwise out-of-band comparisons between every pair of participants.
This verification can occur at any time before the DKG session is finalized, in particular before the start of the session.

[^trust-anchor]: No protocol can prevent man-in-the-middle attacks without this or a comparable assumption.
Note that this requirement is implicit in other schemes as well.
For example, setting up a multi-signature wallet via non-interactive key aggregation in MuSig2 [[BIP 327](bip-0327.mediawiki)]
also requires the assumption that all participants have authentic copies of each other's individual public keys.

#### Equality Check Protocol CertEq

The CertEq protocol is straightforward:[^certeq-literature]
Every participant sends a signature on their input value `eq_input` to every other participant (via the untrusted coordinator),
and expects to receive valid signatures on `eq_input` from the other participants.
A participant terminates successfully as soon as the participant has collected what we call a *success certificate*,
i.e., a full list of valid signatures from all `n` participants (including themselves).[^multisig-cert]

[^multisig-cert]: Abstractly, the required primitive is a multi-signature scheme, i.e., `n` participants signing the same message `eq_input`.
We have chosen the naive scheme of collecting a list of `n` individual signatures for simplicity.
Other multi-signatures schemes,
e.g., MuSig2 [[BIP 327](bip-0327.mediawiki)] or a scheme based on Schnorr signature half aggregation [[Halfagg-BIP-Draft](https://github.com/BlockstreamResearch/cross-input-aggregation/blob/master/half-aggregation.mediawiki), [CGKN21](https://eprint.iacr.org/2021/350), [CZ22](https://eprint.iacr.org/2022/222)],
could be used instead to reduce the size of the success certificate.
These methods are out of scope of this document.

[^certeq-literature]: CertEq can be viewed as a signed variant of the Goldwasser-Lindell echo broadcast protocol [[GL05](https://eprint.iacr.org/2002/040), Protocol 1], or alternatively, as a unanimous variant of Signed Echo Broadcast [[Rei94](https://doi.org/10.1145/191177.191194), Section 4], [[CGR11](https://doi.org/10.1007/978-3-642-15260-3), Algorithm 3.17].)

This termination rule immediately implies the integrity property:
Unless a signature has been forged, if some honest participant with input `eq_input` terminates successfully,
then by construction, all other honest participants have sent a signature on `eq_input` and thus received `eq_input` as input.

The key insight to ensuring conditional agreement is that any participant terminating successfully
obtains a *success certificate* `cert` consisting of the collected list of all `n` signatures on `eq_input`.
This certificate will, by the above termination rule, convince every other honest participant (who, by integrity, has received `eq_input` as input) to terminate successfully.
Crucially, this other honest participant will be convinced even after having received invalid or no signatures during the actual run of CertEq,
due to unreliable networks, a faulty coordinator, or faulty participants signing more than one value.

Thus, the certificate does not need to be sent during a normal run of CertEq,
but can instead be presented to other participants later,
e.g., during a request to participate in a FROST signing session.

#### Facilitating Backup and Recovery

ChillDKG constructs a transcript `eq_input` by appending to the transcript of EncPedPop the vector `enc_secshare`.
This ensures that all participants agree on all encrypted shares,
and as a consequence,
the entire DKG output of a successful ChillDKG participant can be deterministically reproduced from a per-participant *host secret key* and the transcript.

This property is leveraged to offer a backup and recovery functionality:
ChillDKG outputs a string called *recovery data* which is the concatenation of the transcript `eq_input` and the success certificate `cert`.
The recovery data, which is the same for every participant, can be used by any participant together with the host secret key to recover the full output of the DKG session.

Crucially, the recovery data carries proof that the DKG session took place:
any recovering participant can extract their own valid signature on the transcript from the success certificate.
This valid signature proves that the participant, or more precisely, their former instance,
had successfully reached the state at which this signature is sent to the coordinator.
In particular, this implies that the proofs of possession from all participants,
which are omitted in recovery data for succinctness,
had been checked successfully.

In fact, the recovery procedure subsumes the handling of a valid success certificate
which is presented to the participant only after the session
(in case an invalid or no certificate was received during the session).
As a result, ChillDKG does not provide a dedicated method for providing a success certificate after the session,
and callers can simply use the recovery functionality instead.

## Usage of ChillDKG

The purpose of this section is to provide a high-level overview of the interface and usage of ChillDKG,
aimed at developers who would like to use a ChillDKG implementation in their applications and systems.

Detailed API documentation of the reference implementation is provided in [Subsection "API Documentation"](#api-documentation).
Developers who would like to implement ChillDKG or understand ChillDKG's internals and reference implementation
should also read [Section "Internals of ChillDKG"](#internals-of-chilldkg).

### Use ChillDKG only for FROST

ChillDKG is designed for usage with the FROST Schnorr signature scheme,
and its security depends on the specifics of FROST.
We stress that ChillDKG is not a general-purpose DKG protocol,[^no-simulatable-dkg]
and **must not** be combined with other threshold cryptographic schemes,
e.g., threshold signature schemes other than FROST, or threshold decryption schemes,
without careful further consideration, which is not in the scope of this document.

[^no-simulatable-dkg]: As a variant of Pedersen DKG, ChillDKG does not provide simulation-based security [GJKR07](https://doi.org/10.1007/s00145-006-0347-3). Roughly speaking, if ChillDKG is combined with some threshold cryptographic scheme, the security of the combination is not automatically implied by the security of the two components. Instead, the security of every combination must be analyzed separately. The security of the specific combination of SimplPedPop (as the core building block of ChillDKG) and FROST has been analyzed [CGRS23](https://eprint.iacr.org/2023/899).

### Protocol Parties and Network Setup

There are `n >= 2` *participants*, `t` of which will be required to produce a signature.
Each participant has a point-to-point communication link to the *coordinator*
(but participants do not have direct communication links to each other).

If there is no dedicated coordinator, one of the participants can act as the coordinator.

Each participant and the coordinator, and the communication links may either be *honest*, i.e., reliable and adhering to the protocol, or *faulty*, i.e., controlled by an attacker or unreliable (e.g., due to software bugs).

### Inputs and Output

The inputs of a session consist of a long-term *host secret key* (individual to each participant, not provided by the coordinator) and public *session parameters* (common to all participants and the coordinator).

If a session ChillDKG returns an output to a participant or the coordinator,
then we say that this party *deems the protocol session successful*.
In that case, the DKG output is a triple consisting of a *secret share* for participating in FROST signing sessions (individual to each participant, not returned to the coordinator), the *threshold public key* representing the `t`-of-`n` policy of the group (common to all participants and the coordinator), and a list of `n` *public shares* for verification of individual contributions to a FROST signing session (common to all participants and the coordinator).
Moreover, all parties obtain *recovery data* (common to all participants and the coordinator), whose purpose is detailed in the next subsection.

To participate in the FROST signing protocol, signers need their DKG output and their index in the host public key list, although the full list of host public keys is not required for signing.
Additionally, the set of indices of all participating signers within the host public key list is required to initiate a signing session.

### Backup and Recovery

Losing the secret share or the threshold public key, e.g., after the loss of a participant device, will render the participant incapable of participating in signing sessions.
As these values depend on the contributions of the other participants to the DKG session, they can,
unlike deterministically derived secret keys [[BIP 32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)] as typically used for single-signer Schnorr signatures [[BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)] or MuSig [[BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)],
not be rederived solely from the participant's seed.

To facilitate backups of a DKG session,
ChillDKG offers the possibility to recover a participant's DKG output from the participant's host secret key and the recovery data of the specific session,
As a result, a full backup of a participant consists of the host secret key as well as the recovery data of all DKG sessions the participant has successfully participated in.

Since the recovery data is the same for all participants,
if a participant loses the backup of the recovery data of the DKG session,
they can request it from any other participants or the coordinator.
Moreover, the recovery data contains secrets only in encrypted form and is self-authenticating
so that it can, in principle, be stored with an untrusted third-party backup provider.

Users **should** be aware that the session parameters (the threshold and the host public keys) and public parts of the DKG output (the threshold public key and the public shares) can be inferred from the recovery data, which may constitute a privacy issue.
To eliminate this issue, users can encrypt the recovery data using an encryption key derived from their host secret key before publishing the data.
Recovery from encrypted data requires only the participant's host secret key, with no additional secrets needed.
This BIP does not specify the encryption scheme.

Keeping backups of the secret key accessible and secure is hard (typically similarly hard as keeping the participant devices themselves).
As a consequence, it may not be an unreasonable strategy in a threshold setup not to perform backups of host secret keys at all,
and simply hope that `t` honest and working participants will remain available.
As soon as one or more participants are lost or broken, a new DKG session can be performed with the lost participants replaced.
The obvious drawback of this method is that it will result in a change of the threshold public key,
and the application will, therefore, need to transition to the new threshold public key,
e.g., funds stored under the current threshold public key need to be transferred to the new key.

Whether to perform backups of host secret keys and how to manage them ultimately depends on the requirements of the application,
and we believe that a general recommendation is not useful.

### Recovering Stuck Parties

The mere fact that a protocol party deems a ChillDKG session successful does not imply that other parties deem it successful yet.
Indeed, due to failing communication links or invalid messages sent by faulty parties,
it is possible that one party has deemed the DKG session successful, but others have not (yet) and thus are stuck in the DKG session.
In that case, the successful parties can eventually convince the stuck parties to consider the DKG session successful by presenting the recovery data to them.
The recovery data can, e.g., be attached to the first request to initiate a FROST signing session.

An important implication of the above is that anyone who uses the threshold public key,
and thereby relies on the participants' ability to participate in signing sessions,
**must** ensure that the participants have already deemed the DKG session successful,
or at least, that the recovery data will be available to convince any stuck participants of the success of the DKG session.

For an example of what could go wrong,
assume that some participant deems the DKG session successful and uses the threshold public key by sending funds to some Bitcoin address derived from it.
Even though everything looks fine from the perspective of this participant,
it is entirely possible that this participant is the only one who has deemed the DKG session successful,
and thus (besides the untrusted coordinator) the only one who knows the recovery data.
If the recovery data is lost now because this participant's permanent storage fails,
the other participants cannot be convinced to deem the DKG session successful
(without the help of the untrusted coordinator)
and so the funds will be lost.

Thus, anyone who intends to use the threshold public key
**should** first obtain explicit confirmations from all participants that they have deemed the DKG session successful,
which will also imply that all participants have a redundant copy of the recovery data.
One simple method of obtaining confirmation is to collect signed confirmation messages from all participants.

Depending on the application, other methods may be appropriate.
For example, in a scenario where a single user employs multiple signing devices in the same room to set up a threshold wallet,
the user could check that all `n` devices signal confirmation via its display.
Alternatively, the user could check all `n` devices when generating a receiving address for the first time,
which constitutes the first use of the threshold public key.

If a recovering party (see [Backup and Recovery](#backup-and-recovery)) cannot (re-)obtain confirmations,
this simply means they **should** stop using the threshold public key going forward,
e.g., stop sending additional funds to addresses derived from it.
(But, in contrast to the bad example laid out above,
it will still be possible to spend the funds,
and even recovered participants can participate in signing sessions.)

### Blaming Faulty Parties

Any faulty party can make a ChillDKG session abort by sending a message that deviates from the protocol specification.
To help resolve the underlying problem, ChillDKG provides a *blame functionality*
that enables honest protocol parties to identify and blame at least one participant suspected to be faulty:
 - If an honest participant aborts the session, then this participant will blame at least one participant or the coordinator.
 - If an honest coordinator aborts the session, then the coordinator then will blame at least one participant.

Moreover, a party which, instead of aborting after having received an invalid protocol message,
aborts due to a timeout while waiting for a protocol message
will trivially blame the party who is supposed to send the outstanding message.

The guarantees provided by the blame functionality are limited,
and its primary purpose is to support manual investigation and debugging efforts.
Different parties, even if honest, are not guaranteed to blame the same party,
and there is, in general, no way to verify an accusation by some party that another party is to blame.
Nevertheless, if all messages in the ChillDKG session have been transmitted correctly over the communication links,
and, in case of a participant blaming another participant, if the coordinator is additionally honest,
the aborting party will be guaranteed that the blamed party is indeed faulty.

It is important to understand that this guarantee is conditional.
For example, assume that the condition of a honest coordinator is violated.
In that case, even if all participants are honest, the malicious coordinator can deviate from the protocol in a way that makes one participant blame another participant, when, in fact, it is the coordinator who is faulty and not the blamed participant.

In some cases,[^incorrect-shares] an aborting participant needs to obtain an auxiliary *investigation message* from the coordinator
in order to single out and blame another participant (see [Overview of a ChillDKG session](#overview-of-a-chilldkg-session)).

[^incorrect-shares]: Namely, when having received incorrect secret shares.

### Threat Model and Security Goals

We expect ChillDKG to provide the following informal security goals when it is used to set up keys for the FROST threshold signature scheme.
If a participant deems a protocol session successful (as defined in [Inputs and Outputs](#inputs-and-outputs)), then this participant is assured that:
 - A coalition of at most `t - 1` faulty participants and a faulty coordinator cannot forge a signature under the returned threshold public key on any message `m` for which no signing session with at least one honest participant was initiated. (Unforgeability)[^unforgeability-formal]
 - All honest participants who deem the protocol session successful will have correct and consistent protocol outputs.
   In particular, they agree on the threshold public key, the list of public shares, and the recovery data.
   Moreover, any `t` of them have secret shares consistent with the threshold public key.[^correctness-formal]
   This means that any `t` participants have all the necessary inputs to run FROST signing sessions which produce signatures valid under the threshold public key.
 - The success certificate will, when presented to any other (honest) participant, convince that other participant to deem the protocol successful.

[^unforgeability-formal]: See Chu, Gerhart, Ruffing, and Schröder [Definition 3, [CGRS23](https://eprint.iacr.org/2023/899)] for a formal definition.

[^correctness-formal]: See Ruffing, Ronge, Jin, Schneider-Bensch, and Schröder [Definition 2.5, [RRJSS22](https://eprint.iacr.org/2022/550)] for a formal definition.

### Overview of a ChillDKG Session

(See also [`python/example.py`](python/example.py).)

The following figure shows an example ChillDKG involving the participants and the coordinator.
For simplicity, only one participant is depicted.
Arrows indicate network messages between the parties.
Each message sent by the coordinator is a broadcast message,
i.e., the coordinator sends the same message to each participant.[^no-reliable-broadcast]
Unless participants abort due to errors, all participants run the same code and send messages in the same steps.

[^no-reliable-broadcast]: Recall that we do not assume a *reliable* broadcast channel but instead that the coordinator has separate a point-to-point communication links to each participant. In other words, the protocol prescribes that an honest coordinator sends the same message to every participant, but the security of the protocol does not depend on the coordinator adhering to that prescribe.

TODO Add on-wire messages sizes to the figure after defining message serialization format.

![The figure shows the message flow between a participant and a coordinator.
The first of two phases named "Generation of host public keys" involves the participant invoking the hostpubkey_gen function with parameter hostseckey and sending the returned hostpubkey to the coordinator.
The second phase named "Session" is initiated by the coordinator sending hostpubkeys and the threshold t to the participant.
The participant invokes participant_step1 and sends the returned pmsg1 to the coordinator.
The coordinator invokes coordinator_step1 and sends the returned cmsg1 to the participant.
The participant invokes participant_step2 and sends the returned pmsg2 to the coordinator.
The coordinator invokes coordinator_finalize and sends the returned cmsg2 to the participant.
The participant invokes participant_finalize, which ends the second phase.
](images/chilldkg-sequence.png "ChillDKG")

A participant can run multiple sessions with the same hostseckey, provided that the session state as output from any of the "step" functions is not reused.
Multiple sessions may be run concurrently.

Whenever an invoked function fails and raises an error, the corresponding party will abort the session and,
in most cases, blame a participant or the coordinator for the failure of the session.
However, if a participant aborts during the `participant_step2` function,
there may be insufficient information determine another participant to blame.
In this case, an optional *investigation procedure* is available:
The aborting participant can ask the coordinator for an auxiliary *investigation message* (generated via the `coordinator_investigate` function),
which will allow the participant to blame a specific other participant (via the `participant_investigate` function).

Applications may choose to let the coordinator always create and send investigation messages,
(i.e., even if not asked for by an aborting participant).
While different aborting participants will need different investigation messages,
an investigation message intended for some participant does not to be kept confidential from other participants.
Thus, applications may additionally choose to let the coordinator send all `n` investigation messages to all `n` participants.

### API Documentation

This subsection is an export of the API documentation generated from the docstrings in the reference implementation
(see [`python/chilldkg_ref/chilldkg.py`](python/chilldkg_ref/chilldkg.py).)

<!--pydoc.md-->
#### hostpubkey\_gen

```python
def hostpubkey_gen(hostseckey: bytes) -> bytes
```

Compute the participant's host public key from the host secret key.

The host public key is the long-term cryptographic identity of the
participant.

This function interprets `hostseckey` as big-endian integer, and computes
the corresponding "plain" public key in compressed serialization (33 bytes,
starting with 0x02 or 0x03). This is the key generation procedure
traditionally used in Bitcoin, e.g., for ECDSA. In other words, this
function is equivalent to `IndividualPubkey` as defined in
[[BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-generation-of-an-individual-signer)].
TODO Refer to the FROST signing BIP instead, once that one has a number.

*Arguments*:

- `hostseckey` - This participant's long-term secret key (32 bytes).
  The key **must** be 32 bytes of cryptographically secure randomness
  with sufficient entropy to be unpredictable. All outputs of a
  successful participant in a session can be recovered from (a backup
  of) the key and per-session recovery data.

  The same host secret key (and thus the same host public key) can be
  used in multiple DKG sessions. A host public key can be correlated
  to the threshold public key resulting from a DKG session only by
  parties who observed the session, namely the participants, the
  coordinator (and any eavesdropper).


*Returns*:

  The host public key (33 bytes).


*Raises*:

- `HostSeckeyError` - If the length of `hostseckey` is not 32 bytes or if the
  key is invalid.

#### HostSeckeyError Exception

```python
class HostSeckeyError(ValueError)
```

Raised if the host secret key is invalid.

This incluces the case that its length is not 32 bytes.

#### SessionParams Tuples

```python
class SessionParams(NamedTuple):
    hostpubkeys: List[bytes]
    t: int
```

A `SessionParams` tuple holds the common parameters of a DKG session.

*Attributes*:

- `hostpubkeys` - Ordered list of the host public keys of all participants.
- `t` - The participation threshold `t`.
  This is the number of participants that will be required to sign.
  It must hold that `1 <= t <= len(hostpubkeys) <= 2**32 - 1`.

  Participants **must** ensure that they have obtained authentic host
  public keys of all the other participants in the session to make
  sure that they run the DKG and generate a threshold public key with
  the intended set of participants. This is analogous to traditional
  threshold signatures (known as "multisig" in the Bitcoin community),
  [[BIP 383](https://github.com/bitcoin/bips/blob/master/bip-0383.mediawiki)],
  where the participants need to obtain authentic extended public keys
  ("xpubs") from the other participants to generate multisig
  addresses, or MuSig2
  [[BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)],
  where the participants need to obtain authentic individual public
  keys of the other participants to generate an aggregated public key.

  A DKG session will fail if the participants and the coordinator in a session
  don't have the `hostpubkeys` in the same order. This will make sure that
  honest participants agree on the order as part of the session, which is
  useful if the order carries an implicit meaning in the application (e.g., if
  the first `t` participants are the primary participants for signing and the
  others are fallback participants). If there is no canonical order of the
  participants in the application, the caller can sort the list of host public
  keys with the [KeySort algorithm specified in
  BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-sorting)
  to abstract away from the order.

#### params\_id

```python
def params_id(params: SessionParams) -> bytes
```

Return the parameters ID, a unique representation of the `SessionParams`.

In the common scenario that the participants obtain host public keys from
the other participants over channels that do not provide end-to-end
authentication of the sending participant (e.g., if the participants simply
send their unauthenticated host public keys to the coordinator, who is
supposed to relay them to all participants), the parameters ID serves as a
convenient way to perform an out-of-band comparison of all host public keys.
It is a collision-resistant cryptographic hash of the `SessionParams`
tuple. As a result, if all participants have obtained an identical
parameters ID (as can be verified out-of-band), then they all agree on all
host public keys and the threshold `t`, and in particular, all participants
have obtained authentic public host keys.

*Returns*:

- `bytes` - The parameters ID, a 32-byte string.


*Raises*:

- `InvalidHostPubkeyError` - If `hostpubkeys` contains an invalid public key.
- `DuplicateHostPubkeyError` - If `hostpubkeys` contains duplicates.
- `ThresholdOrCountError` - If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
  not hold.

#### SessionParamsError Exception

```python
class SessionParamsError(ValueError)
```

Base exception for invalid `SessionParams` tuples.

#### DuplicateHostPubkeyError Exception

```python
class DuplicateHostPubkeyError(SessionParamsError)
```

Raised if two participants have identical host public keys.

This exception is raised when two participants have an identical host public
key in the `SessionParams` tuple. Assuming the host public keys in question
have been transmitted correctly, this exception implies that at least one of
the two participants is faulty (because duplicates occur only with
negligible probability if keys are generated honestly).

*Attributes*:

- `participant1` _int_ - Index of the first participant.
- `participant2` _int_ - Index of the second participant.

#### InvalidHostPubkeyError Exception

```python
class InvalidHostPubkeyError(SessionParamsError)
```

Raised if a host public key is invalid.

This exception is raised when a host public key in the `SessionParams` tuple
is not a valid public key in compressed serialization. Assuming the host
public keys in question has been transmitted correctly, this exception
implies that the corresponding participant is faulty.

*Attributes*:

- `participant` _int_ - Index of the participant.

#### ThresholdOrCountError Exception

```python
class ThresholdOrCountError(SessionParamsError)
```

Raised if `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does not hold.

#### DKGOutput Tuples

```python
class DKGOutput(NamedTuple):
    secshare: Optional[bytes]
    threshold_pubkey: bytes
    pubshares: List[bytes]
```

Holds the outputs of a DKG session.

*Attributes*:

- `secshare` - Secret share of the participant (or `None` for coordinator)
- `threshold_pubkey` - Generated threshold public key representing the group
- `pubshares` - Public shares of the participants

#### participant\_step1

```python
def participant_step1(hostseckey: bytes, params: SessionParams, random: bytes) -> Tuple[ParticipantState1, ParticipantMsg1]
```

Perform a participant's first step of a ChillDKG session.

*Arguments*:

- `hostseckey` - Participant's long-term host secret key (32 bytes).
- `params` - Common session parameters.
- `random` - FRESH random byte string (32 bytes).


*Returns*:

- `ParticipantState1` - The participant's session state after this step, to
  be passed as an argument to `participant_step2`. The state **must
  not** be reused (i.e., it must be passed only to one
  `participant_step2` call).
- `ParticipantMsg1` - The first message to be sent to the coordinator.


*Raises*:

- `HostSeckeyError` - If the length of `hostseckey` is not 32 bytes, if the
  key is invalid, or if the key does not match any entry of
  `hostpubkeys`.
- `InvalidHostPubkeyError` - If `hostpubkeys` contains an invalid public key.
- `DuplicateHostPubkeyError` - If `hostpubkeys` contains duplicates.
- `ThresholdOrCountError` - If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
  not hold.
- `RandomnessError` - If the length of `random` is not 32 bytes.

#### RandomnessError Exception

```python
class RandomnessError(ValueError)
```

Raised if the length of the provided randomness is not 32 bytes.

#### participant\_step2

```python
def participant_step2(hostseckey: bytes, state1: ParticipantState1, cmsg1: CoordinatorMsg1) -> Tuple[ParticipantState2, ParticipantMsg2]
```

Perform a participant's second step of a ChillDKG session.

*Warning:*
After sending the returned message to the coordinator, this participant
**must not** erase the hostseckey, even if this participant does not receive
the coordinator reply needed for the `participant_finalize` call. The
underlying reason is that some other participant may receive the coordinator
reply, deem the DKG session successful and use the resulting threshold
public key (e.g., by sending funds to it). If the coordinator reply remains
missing, that other participant can, at any point in the future, convince
this participant of the success of the DKG session by presenting recovery
data, from which this participant can recover the DKG output using the
`recover` function.

*Arguments*:

- `hostseckey` - Participant's long-term host secret key (32 bytes).
- `state1` - The participant's session state as output by
  `participant_step1`.
- `cmsg1` - The first message received from the coordinator.


*Returns*:

- `ParticipantState2` - The participant's session state after this step, to
  be passed as an argument to `participant_finalize`. The state **must
  not** be reused (i.e., it must be passed only to one
  `participant_finalize` call).
- `ParticipantMsg2` - The second message to be sent to the coordinator.


*Raises*:

- `HostSeckeyError` - If the length of `hostseckey` is not 32 bytes.
- `FaultyCoordinatorError` - If the coordinator is faulty. See the
  documentation of the exception for further details.
- `FaultyParticipantOrCoordinatorError` - If another known participant or the
  coordinator is faulty. See the documentation of the exception for
  further details.
- `UnknownFaultyParticipantOrCoordinatorError` - If another unknown
  participant or the coordinator is faulty, but running the optional
  investigation procedure of the protocol is necessary to determine a
  suspected participant. See the documentation of the exception for
  further details.

#### participant\_finalize

```python
def participant_finalize(state2: ParticipantState2, cmsg2: CoordinatorMsg2) -> Tuple[DKGOutput, RecoveryData]
```

Perform a participant's final step of a ChillDKG session.

If this function returns properly (without an exception), then this
participant deems the DKG session successful. It is, however, possible that
other participants have received a `cmsg2` from the coordinator that made
them raise an exception instead, or that they have not received a `cmsg2`
from the coordinator at all. These participants can, at any point in time in
the future (e.g., when initiating a signing session), be convinced to deem
the session successful by presenting the recovery data to them, from which
they can recover the DKG outputs using the `recover` function.

*Warning:*
Changing perspectives, this implies that, even when obtaining an exception,
this participant **must not** conclude that the DKG session has failed, and
as a consequence, this particiant **must not** erase the hostseckey. The
underlying reason is that some other participant may deem the DKG session
successful and use the resulting threshold public key (e.g., by sending
funds to it). That other participant can, at any point in the future,
convince this participant of the success of the DKG session by presenting
recovery data to this participant.

*Arguments*:

- `state2` - The participant's state as output by `participant_step2`.
- `cmsg2` - The second message received from the coordinator.


*Returns*:

- `DKGOutput` - The DKG output.
- `bytes` - The serialized recovery data.


*Raises*:

- `FaultyParticipantOrCoordinatorError` - If another known participant or the
  coordinator is faulty. Make sure to read the above warning, and see
  the documentation of the exception for further details.
- `FaultyCoordinatorError` - If the coordinator is faulty. Make sure to read
  the above warning, and see the documentation of the exception for
  further details.

#### participant\_investigate

```python
def participant_investigate(error: UnknownFaultyParticipantOrCoordinatorError, cinv: CoordinatorInvestigationMsg) -> NoReturn
```

Investigate who is to blame for a failed ChillDKG session.

This function can optionally be called when `participant_step2` raises
`UnknownFaultyParticipantOrCoordinatorError`. It narrows down the suspected
faulty parties by analyzing the investigation message provided by the coordinator.

This function does not return normally. Instead, it raises one of two
exceptions.

*Arguments*:

- `error` - `UnknownFaultyParticipantOrCoordinatorError` raised by
  `participant_step2`.
- `cinv` - Coordinator investigation message for this participant as output
  by `coordinator_investigate`.


*Raises*:

- `FaultyParticipantOrCoordinatorError` - If another known participant or the
  coordinator is faulty. See the documentation of the exception for
  further details.
- `FaultyCoordinatorError` - If the coordinator is faulty. See the
  documentation of the exception for further details.

#### coordinator\_step1

```python
def coordinator_step1(pmsgs1: List[ParticipantMsg1], params: SessionParams) -> Tuple[CoordinatorState, CoordinatorMsg1]
```

Perform the coordinator's first step of a ChillDKG session.

*Arguments*:

- `pmsgs1` - List of first messages received from the participants. The
  list's length must equal the total number of participants.
- `params` - Common session parameters.


*Returns*:

- `CoordinatorState` - The coordinator's session state after this step, to be
  passed as an argument to `coordinator_finalize`. The state is not
  supposed to be reused (i.e., it should be passed only to one
  `coordinator_finalize` call).
- `CoordinatorMsg1` - The first message to be sent to all participants.


*Raises*:

- `InvalidHostPubkeyError` - If `hostpubkeys` contains an invalid public key.
- `DuplicateHostPubkeyError` - If `hostpubkeys` contains duplicates.
- `ThresholdOrCountError` - If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
  not hold.
- `FaultyParticipantError` - If another participant is faulty. See the
  documentation of the exception for further details.

#### coordinator\_finalize

```python
def coordinator_finalize(state: CoordinatorState, pmsgs2: List[ParticipantMsg2]) -> Tuple[CoordinatorMsg2, DKGOutput, RecoveryData]
```

Perform the coordinator's final step of a ChillDKG session.

If this function returns properly (without an exception), then the
coordinator deems the DKG session successful. The returned `CoordinatorMsg2`
is supposed to be sent to all participants, who are supposed to pass it as
input to the `participant_finalize` function. It is, however, possible that
some participants pass a wrong and invalid message to `participant_finalize`
(e.g., because the message is transmitted incorrectly). These participants
can, at any point in time in the future (e.g., when initiating a signing
session), be convinced to deem the session successful by presenting the
recovery data to them, from which they can recover the DKG outputs using the
`recover` function.

If this function raises an exception, then the DKG session was not
successful from the perspective of the coordinator. In this case, it is, in
principle, possible to recover the DKG outputs of the coordinator using the
recovery data from a successful participant, should one exist. Any such
successful participant is either faulty, or has received messages from
other participants via a communication channel beside the coordinator.

*Arguments*:

- `state` - The coordinator's session state as output by `coordinator_step1`.
- `pmsgs2` - List of second messages received from the participants. The
  list's length must equal the total number of participants.


*Returns*:

- `CoordinatorMsg2` - The second message to be sent to all participants.
- `DKGOutput` - The DKG output. Since the coordinator does not have a secret
  share, the DKG output will have the `secshare` field set to `None`.
- `bytes` - The serialized recovery data.


*Raises*:

- `FaultyParticipantError` - If another participant is faulty. See the
  documentation of the exception for further details.

#### coordinator\_investigate

```python
def coordinator_investigate(pmsgs: List[ParticipantMsg1]) -> List[CoordinatorInvestigationMsg]
```

Generate investigation messages for a ChillDKG session.

The investigation messages will allow the participants to investigate who is
to blame for a failed ChillDKG session (see `participant_investigate`).

Each message is intended for a single participant but can be safely
broadcast to all participants because the messages contain no confidential
information.

*Arguments*:

- `pmsgs` - List of first messages received from the participants.


*Returns*:

- `List[CoordinatorInvestigationMsg]` - A list of investigation messages, each
  intended for a single participant.

#### recover

```python
def recover(hostseckey: Optional[bytes], recovery_data: RecoveryData) -> Tuple[DKGOutput, SessionParams]
```

Recover the DKG output of a ChillDKG session.

This function serves two different purposes:
1. To recover from an exception in `participant_finalize` or
`coordinator_finalize`, after obtaining the recovery data from another
participant or the coordinator. See `participant_finalize` and
`coordinator_finalize` for background.
2. To reproduce the DKG outputs on a new device, e.g., to recover from a
backup after data loss.

*Arguments*:

- `hostseckey` - This participant's long-term host secret key (32 bytes) or
  `None` if recovering the coordinator.
- `recovery_data` - Recovery data from a successful session.


*Returns*:

- `DKGOutput` - The recovered DKG output.
- `SessionParams` - The common parameters of the recovered session.


*Raises*:

- `HostSeckeyError` - If the length of `hostseckey` is not 32 bytes, if the
  key is invalid, or if the key does not match the recovery data.
  (This can also occur if the recovery data is invalid.)
- `RecoveryDataError` - If recovery failed due to invalid recovery data.

#### RecoveryDataError Exception

```python
class RecoveryDataError(ValueError)
```

Raised if the recovery data is invalid.

#### ProtocolError Exception

```python
class ProtocolError(Exception)
```

Base exception for errors caused by received protocol messages.

#### FaultyParticipantError Exception

```python
class FaultyParticipantError(ProtocolError)
```

Raised if a participant is faulty.

This exception is raised by the coordinator code when it detects faulty
behavior by a participant, i.e., a participant has deviated from the
protocol. The index of the participant is provided as part of the exception.
Assuming protocol messages have been transmitted correctly and the
coordinator itself is not faulty, this exception implies that the
participant is indeed faulty.

This exception is raised only by the coordinator code. Some faulty behavior
by participants will be detected by the other participants instead.
See `FaultyParticipantOrCoordinatorError` for details.

*Attributes*:

- `participant` _int_ - Index of the faulty participant.

#### FaultyParticipantOrCoordinatorError Exception

```python
class FaultyParticipantOrCoordinatorError(ProtocolError)
```

Raised if another known participant or the coordinator is faulty.

This exception is raised by the participant code when it detects what looks
like faulty behavior by a suspected participant. The index of the suspected
participant is provided as part of the exception.

Importantly, this exception is not proof that the suspected participant is
indeed faulty. It is instead possible that the coordinator has deviated from
the protocol in a way that makes it look as if the suspected participant has
deviated from the protocol. In other words, assuming messages have been
transmitted correctly and the raising participant is not faulty, this
exception implies that
- the suspected participant is faulty,
- *or* the coordinator is faulty (and has framed the suspected
participant).

This exception is raised only by the participant code. Some faulty behavior
by participants will be detected by the coordinator instead. See
`FaultyParticipantError` for details.

*Attributes*:

- `participant` _int_ - Index of the suspected participant.

#### FaultyCoordinatorError Exception

```python
class FaultyCoordinatorError(ProtocolError)
```

Raised if the coordinator is faulty.

This exception is raised by the participant code when it detects faulty
behavior by the coordinator, i.e., the coordinator has deviated from the
protocol. Assuming protocol messages have been transmitted correctly and the
raising participant is not faulty, this exception implies that the
coordinator is indeed faulty.

#### UnknownFaultyParticipantOrCoordinatorError Exception

```python
class UnknownFaultyParticipantOrCoordinatorError(ProtocolError)
```

Raised if another unknown participant or the coordinator is faulty.

This exception is raised by the participant code when it detects what looks
like faulty behavior by some other participant, but there is insufficient
information to determine which participant should be suspected.

To determine a suspected participant, the raising participant may choose to
run the optional investigation procedure of the protocol, which requires
obtaining an investigation message from the coordinator. See the
`participant_investigate` function for details.

This is only raised for specific faulty behavior by another participant
which cannot be attributed to another participant without further help of
the coordinator (namely, sending invalid encrypted secret shares).

*Attributes*:

- `inv_data` - Information required to perform the investigation.
<!--end of pydoc.md-->

## Changelog

To help the reader understand updates to this document, we attach a version number that resembles "semantic versioning" (`MAJOR.MINOR.PATCH`).
The `MAJOR` version is incremented if changes to the BIP are introduced that are incompatible with prior versions.
An exception to this rule is `MAJOR` version zero (0.y.z) which is for development and does not need to be incremented if backwards-incompatible changes are introduced.
The `MINOR` version is incremented whenever the inputs or the output of an algorithm changes in a backward-compatible way or new backward-compatible functionality is added.
The `PATCH` version is incremented for other noteworthy changes (bug fixes, test vectors, important clarifications, etc.).

* *0.2.0* (2024-12-19): In addition to various readability improvements to specification and reference implementation, the following major changes were implemented:
  * Fix security vulnerability where the CertEq signature did not cover the entire message.
  * Add blame functionality to identify faulty parties, including an investigation phase.
  * Make threshold public key Taproot-safe by default.
  * Let each participant encrypt the secret share intended for themselves so that it can be decrypted instead of re-derived during recovery. The encryption is symmetric to avoid the overhead of an ECDH computation.
* *0.1.0* (2024-07-08): Publication of draft BIP on the bitcoin-dev mailing list

## Acknowledgments

We thank Lloyd Fournier (LLFourn) and Sivaram (siv2r) for their comments and contributions to this document.
