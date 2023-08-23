# FROST module DKG

## DKG Pseudocode
[dkg.py](dkg.py)

## Design
- What are the setup assumptions?
    - are there some secp256k1 public keys already for the signers that we assume to be distributed?
    - are there authenticated channels between the signers?
    - we could instantiate a simple secure channel with just encryption and `Eq` (see SecurePedPop)
- Do we want to entirely skip blaming in the DKG or do we want to at least support some basic form that allows identifying faulty but not actively malicious signers.
- Need to document that we shouldn't throw away data until we're sure that the DKG either failed or succeeded. Otherwise, the DKG may end up succeeding after throwing away and someone sends funds to the address.
- How modular do we want to design this? Do we support plugging in other DKGs?
- Do we want to support some sort of share backup scheme (see also [repairable threshold sigs](https://github.com/chelseakomlo/talks/blob/master/2019-combinatorial-schemes/A_Survey_and_Refinement_of_Repairable_Threshold_Schemes.pdf))that sends share encrypted-to-self to other signers? As long as one other signer cooperates we can restore.
- Are we able to get rid of indices entirely? SimplPedPop uses indices, JessePedPop doesn't. It uses public keys instead.
  - use unique identifier instead of pubkey?
- Into how many functions should we split up the DKG. Jesse claims that splitting up has the advantage that "it's more flexible because with the proposed API the VSS can be generated prior to knowing the public keys of any participants"
- Should it be possible to assign weights for weighted threshold sigs?
- Do we need to include the signature in the vss_hash? Probably not, but depending on how the rest is set up, it may not hurt.
- Should the scheme support deterministic key derivation?
   - Not sure if that's actually that useful. And it only works as long as the code does not change, which we may not want to guarantee.
- Is it impossible to sign if the `Eq` check fails? If not, we may want to tweak the public key by `eta` to make sure that signing fails.


## Jonas' Favorites

We want to design both the BIP and the implementation such that they are modular enough to allow replacing the DKG.

The best cost-benefit tradeoff: SimplPedPop with

- signer public keys
- unique, global signer ids (could be index or pubkey) instead of indices
  - It should be fine for unforgeability if signer ids end up not being unique.
  - Using public keys as IDs is not ideal because this requires distributing secp256k1 public keys which would otherwise not be necessary.
    - There are cases where we anyway need secp256k1 public keys, for example, if we instantiate a broadcast channel
  - Note that it would also be possible to use the hash of the signer's vss_commitment, but this requires receiving vss_commitment before sending out the shares
- basic blaming, i.e., be able to determine whose pok or vss_commitment doesn't verify
- a detailed description in the BIP what secure broadcast is and how to achieve it (via echo-broadcast for example)

It **should** be possible to add the following features by just wrapping SimplPedPop:
- secure channels
- encrypt-to-self share backups
- deterministic key derivation

It **may** be possible to add the following features by just wrapping SimplPedPop:
- proper blaming (maybe)
  - Need to signing all messages and post the transcript in the broadcast channel.
  - Somehow need to bind messages to a session to prevent replay (see also [this](https://github.com/BlockstreamResearch/secp256k1-zkp/pull/138#pullrequestreview-998378598)). Not clear how to come up with a unique session id.
  - This requires that the signers already agree on the individual public keys. If there's disagreement, the signature is worthless
- rekeying, key rotation, repairs?

It's probably **not** possible to add the following features by just wrapping SimplPedPop:
- secure channels without additional public keys (see [SecPedPop](dkg.py))
  - this is elegant and only requires encrypting a single message
- weights

### BIP

We should mention that before sending funds to an address the signers should've created a signature.

We should clearly specify what secure broadcast is and how to achieve it.
For example, we need the property that if a honest signer believes the DKG has run successfully, no other honest signer believes the DKG failed (it may be in an indeterminate state forever though).


### API

We split the functions such that you can generate vss_commitment and pok before knowing pubkey (or signer id). I think this makes sense.
But actually if you want to generate before, just assign dummy ids.
