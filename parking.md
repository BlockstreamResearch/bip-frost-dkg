## Parking Lot

### Design
Consequently, unlike SimplPedPop, EncPedPop does not require pre-existing secure channels between the signers.

|                 | seed              | requires secure channels | equality check protocol included | backup                             | Recommended  |
|-----------------|-------------------|--------------------------|----------------------------------|------------------------------------|--------------|
| **SimplPedPop** | fresh             | yes                      | no                               | share per setup                    | no           |
| **EncPedPop**   | reuse allowed     | no                       | no                               | share per setup                    | yes, with Eq |
| **RecPedPop**   | reuse for backups | no                       | yes                              | seed + public transcript per setup | yes          |

Flexibility: Moreover, they support situations where backup information is required to be written down manually, as well as those with ample backup space.

### SimplePedPop
SimplPedPop requires SECURE point-to-point channels for transferring secret shares between participants - that is, channels that are both ENCRYPTED and AUTHENTICATED.
These messages can be relayed through the coordinator who is responsible to pass the messages to the participants as long as the coordinator cannot interfere with the secure channels between the participants.

Also, SimplePedPop requires an interactive equality check protocol `Eq` as described in section [Equality Protocol](#equality-protocol).
While SimplPedPop is able to identify participants who are misbehaving in certain ways, it is easy for a participant to misbehave such that it will not be identified.

In SimplPedPop, the signers designate a coordinator who relays and aggregates messages.
Every participant runs the `simplpedpop` algorithm and the coordinator runs the `simplpedpop_coordinate` algorithm as described below.

### EncPedPop in optimistic mode (= equality check takes care of authenticity at the end)

- EncPedPod takes care not only of encrypting shares but also of authenticity, which is established via the equality check protocol.
- Note that if the public keys are not distributed correctly or the messages have been tampered with, `Eq(eta)` will fail.

### Backup and Recovery (EndPedPop)
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
    def encpedpop_recover(seed, enc_secshare, t, enckeys, shared_pubkey, signer_pubkeys):
        my_deckey = kdf(seed, "deckey")
        enc_context = hash([t] + enckeys)
        secshare = enc_secshare - sum_scalar([ecdh(my_deckey, enckeys[i], enc_context) for i in range(n)]
        return secshare, shared_pubkey, signer_pubkeys

    # my_idx is required for signing
    def encpedpop_recover_my_idx(seed, enc_secshare, t, enckeys, shared_pubkey, signer_pubkeys):
        return enckeys.index(my_enckey)
    ```
    If the encrypted shares are lost and all other signers are cooperative and have seed backups, then there is also the possibility to re-run the DKG.


### CertEq proof
CertEq  satisfies integrity and conditional agreement.
Proof.
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
