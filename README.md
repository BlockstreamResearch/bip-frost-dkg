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
- Into how many functions should we split up the DKG. Jesse claims that splitting up has the advantage that "it's more flexible because with the proposed API the VSS can be generated prior to knowing the public keys of any participants"
- Should it be possible to assign weights for weighted threshold sigs?
