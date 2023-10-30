# Suggestions for a bip-frost DKG section

At this moment, the following are merely rough ideas rather than finalized suggestions.

## Distributed Key Generation (DKG)

Before being able to create signatures, the FROST signers need to obtain a shared public key and individual key shares that allow to sign for the shared public key.
This can be achieved through a trusted dealer who generates the shared public key and verifiably shares the corresponding secret key with the FROST signers.
If the dealer is dishonest or compromised, or the secret key is not deleted correctly and compromised later, an adversary can forge signatures.

To avoid the single point of failure when trusting the dealer, the signers run an interactive distributed key generation (DKG) protocol.
If the DKG for threshold `t` succeeds from the point of view of a signer and outputs a shared public key, then FROST signatures are unforgeable, i.e., `t` signers are required to cooperate to produce a signature for the shared public key - regardless of how many other participants in the the DKG were dishonest.

To instantiate a DKG there are many possible schemes which differ by the guarantees they provide.
Since DKGs are difficult to implement correctly in practice, this document describes DKGs that are relatively *simple*, namely SimplPedPop and SecPedPop.
However, the DKG can be swapped out for a different one provided it is proven to be secure when used in FROST.

For each signer, the DKG has three outputs: a secret share, the shared public key, and individual public keys for partial signature verification.
The secret share and shared public key are required by a signer to produce signatures and therefore, signers *must* ensure that they are not lost.
You can refer to the [Backup and Recover](#backup-and-recover) section for additional details.

Once the DKG concludes successfully, applications should consider creating a FROST signature with all signers for some test message in order to rule out basic errors in the setup.

### SimplPedPop

We specify the SimplPedPop scheme as described in
[Practical Schnorr Threshold Signatures Without the Algebraic Group Model, section 4](https://eprint.iacr.org/2023/899.pdf)
with the following minor modifications:

- Using [arbitrary 33-byte arrays](https://github.com/frostsnap/frostsnap/issues/72) instead of indices as participant identifiers (IDs). This allows for greater flexibility (e.g., IDs can be long-term public keys on the secp256k1 curve), and avoids the need to agree on a global order of signers upfront. The honest participants must choose their IDs such that no two honest participants have the same ID, because a collision between IDs of honest participants means that some `t` honest signers may not able to produce a signature despite reaching the threshold. (However, if a malicious participant claims to have the same ID as an honest participant, signatures remain unforgeable.) A simple way to exclude ID collisions between honest participants is to let each participant choose a random ID. As long as the IDs are chosen uniformly at random from a large enough space, e.g., random 33-byte arrays or random points on the secp256k1 curve, collisions will happen only with negligible probability.
- Adding individual's signer public keys to the output of the DKG. This allows partial signature verification.
- Very rudimentary ability to identify misbehaving signers in some situations.
- The proof-of-knowledge in the setup does not commit to the prover's ID. This is slightly simpler because it doesn't require the setup algorithm to know take the ID as input.

SimplPedPop requires SECURE point-to-point channels between the participants, i.e., channels that are ENCRYPTED and AUTHENTICATED.
The messages can be relayed through a coordinator who is responsible to pass the messages to the participants as long as the coordinator does not interfere with the secure channels between the participants.

Also, SimplePedPop requires an interactive protocol `Eq` as described in section [Ensuring Agreement](#ensuring-agreement).
It is important to note that with some instantiations of `Eq`, SimplPedPop may fail but the signer still cannot delete any secret key material that was created for the DKG session.

While SimplPedPop is able to identify participants who are misbehaving in certain ways, it is easy for a participant to misbehave such that it will not be identified.

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
    vss_commit = commit_to_coefficients(f)
    # sk is the constant term of f and the dlog of vss_commit[0]
    sk = f[0]
    assert(vss_commit[0] == pubkey_gen(sk))
    sig = sign(sk, "")
    vss_commit = vss_commit || sig
    shares = [ f(hash_sometag(id)) for id in ids ]
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
    :param List[bytes] shares: shares from all participants (including this participant)
    :param eta: Optional argument for extra data that goes into `Eq`
    :return: a final share, the shared pubkey, the individual participants' pubkeys
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
The participants start by generating an ephemeral key pair as per [BIP 327's IndividualPubkey](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-generation-of-an-individual-signer) for encrypting the 32-byte key shares.

TODO: it could actually be any encryption scheme, but e.g. el gamal would be simple to standardize. We also we may want to consider encrypting all traffic. 
TIM: We have to think about desired properties, in particular in combination with signatures (authentication vs signatures -- remember iMessage). https://doc.libsodium.org/public-key_cryptography/authenticated_encryption  -- Does iMessage attack matter here? The received messages are checked but if we use encrypt+sign, then you could just copy the polynomial from another participant... no, the pops should avoid this

```python
def secpedpop_round1(seckey):
    return individual_pk(seckey)
```

The public keys are sent to each other.
Every participant stores the received public keys in the `pubkeys` array.

```python
def secpedpop_round2(seed, t, pubkeys):
    # TODO: optional strengthening of the seed, could also be part of SimplPedPop
    seed = Hash(seed, t, pubkeys)
    vss_commit, shares = simplpedpop_setup(seed, t, pubkeys)
    enc_shares = [encrypt(shares[i], pubkeys[i]) for i in range(len(pubkeys))
    return vss_commit, enc_shares
```

For every other participant `id[i]`, the participant sends `vss_commit` and `enc_shares[i]` through the communication channel.

```python
def secpedpop_finalize(pubkeys, my_pubkey, vss_commit, enc_shares):
  shares = [decrypt(enc_share, sec) for enc_share in enc_shares]
  eta = pubkeys
  return simplpedpop_finalize(pubkeys, my_pubkey, vss_commit, shares, eta):
```

Note that if the public keys are not distributed correctly or the messages have been tampered with, `Eq(eta)` will fail.
However, if `Eq(eta)` does fail, then confidentiality of the share may be broken, which makes it even more important to not reuse seeds.

### Ensuring Agreement
TODO: What about replay protection? Ephemeral pubkeys should guarantee this, at least when they are present and hashed everytime

TODO: Should Eq also take the ids as inputs (and if yes, as part of x)?

TODO: The term agreement is overloaded (used for formal property of Eq and for informal property of DKG). Maybe rename one to consistency? Check the broadcast literature first

A crucial prerequisite for security is that participants reach agreement over the results of the DKG.
Indeed, disagreement may lead to catastrophic failure.
For example, assume that all but one participant believe that DKG has failed and therefore delete their secret key material,
but one participant believes that the DKG has finished successfully and sends funds to the resulting threshold public key.
Then those funds will be lost irrevocably, because, assuming t > 1, the single remaining secret share is not sufficient to produce a signature.

DKG protocols in the cryptographic literature often abstract away from this problem
by assuming that all participants have access to some kind of ideal "reliable broadcast" mechanism, which guarantees that all participants receive the same protocol messages and thereby ensures agreement.
However, it can be hard or even theoretically impossible to realize a reliable broadcast mechanism depending on the specific scenario, e.g., the guarantees provided by the underlying network, and the minimum number of participants assumed to be honest.

The two DKG protocols described above work with a similar but slightly weaker abstraction instead.
They assume that participants have access to an equality check mechanism "Eq", i.e.,
a mechanism that asserts that the input values provided to it by all participants are equal.

TODO Consider removing INDETERMINATE... If we insist on conditional termination, this cannot be an output, it can be at most the state before the output. Then we're back to booleans as in the paper.

Eq has the following abstract interface:
Every participant can invoke Eq(x) with an input value x. When Eq returns for a calling participant, it will return SUCCESS, INDETERMINATE, or FAIL to the calling participant.
 - SUCCESS means that it is guaranteed that all honest participants agree on the value x (but it may be the case that not all of them have established this fact yet). This means that the DKG was successful and the resulting aggregate key can be used, and the generated secret keys need to be retained. It may still be helpful to check with other participants out-of-band that they have all arrived at the SUCCESS state. (TODO explain)
 - FAIL means that it is guaranteed that no honest participant will output SUCCESS. In that case, the generated secret keys can safely be deleted.
 - INDETERMINATE means that it is unknown whether the honest participants agree on the value and whether some honest participants have output SUCCESS.
   In that case, the DKG was potentially successful. Other honest participants may believe that it was successful and may assume that the resulting keys can be used. As a result, the generated keys may not deleted.

More formally, Eq must fulfill the following properties:
 - Integrity: If some honest participant outputs SUCCESS, then for every pair of values x and x' input provided by two honest participants, we have x = x'.
 - Consistency: If some honest participant outputs SUCCESS, no other honest participant outputs FAIL.
 - Conditional Termination: If some honest participant outputs SUCCESS, then all other participants will (eventually) output SUCCESS.
<!-- The latter two properties together are equivalent to Agreement in the paper. -->

Optionally, the following property is desired but not always achievable:
 - (Full) Termination: All honest participants will (eventually) output SUCCESS or FAIL.

#### Examples
TODO: Expand these scenarios. Relate them to SUCCESS, FAIL, INDETERMINATE.

Depending on the application scenario, Eq can be implemented by different protocols, some of which involve out-of-band communication:

##### Participants are in a single room
In a scenario where a single user employs multiple signing devices (e.g., hardware wallets) in the same room to establish a threshold setup, every device can simply display its value x (or a hash of x under a collision-resistant hash function) to the user. The user can manually verify the equality of the values by comparing the values shown on all displays, and confirm their equality by providing explicit confirmation to every device, e.g., by pressing a button on every device.

TODO add failure case, specify entire protocol

Similarly, if signing devices are controlled by different organizations in different geographic locations, agents of these organizations can meet in a single room and compare the values.

These "out-of-band" methods can achieve termination (assuming the involved humans proceed with their tasks eventually).

##### Certifying network-based protocol
TODO The hpk should be the id here... clean this up and write something about setup assumptions

In a network-based scenario, where long-term host keys are available, the equality check can be instantiated by the following protocol:

 - On initialization:
   - Send `sig = sign(hsk, x)` to all other participants
   - Initialize an empty key-value store `cert`, ordered by keys
 - Upon receiving a signature `sig` from participant `hpk`:
   - If `sig[hpk]` is not yet defined and `verify(hpk, sig, x) == true`:
     - Store `sigs[hpk] = sig`
     - If a valid signature was received from all other participants (i.e., `if sigs.keys() = hpks`):
       - Return SUCCESS
       - Send `cert = array(sigs.values())` to all other participants
 - Upon receiving a value `cert`:
     - Parse `cert` as a list of signatures; break this "upon" block if parsing fails.
     - If for all `i=0..n-1`, `verify(hpk[i], sig[i], x) == true`
       - Return SUCCESS
       - Send `cert` to all other participants

In practice, the certificate can also be attached to signing requests instead of sending it to every participant after returning SUCCESS.

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

TODO Consider a variant based on MuSig2

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
