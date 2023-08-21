FROST module DKG
```python
# As described in the Olaf paper
def simplpedpop(secure_chan, seed, t, n):
  vss_commit, gend_shares = share(seed, t, n)
  pk = pubkey_gen(seed)
  sig = sign(seed, i)
  for i in n:
    secure_chan.send(i, pk + sig  + vss_commit + gend_shares[i])
  nu = ()
  for i in n:
    pk[i], sig, vss_commit, shares[i] = secure_chan.receive(i)
    if not verify(vss_commit[i], shares[i]) or not verify(sig, pk[i], i)
      return False
    nu += (sig, vss_commit)
  if not Eq(nu):
    return False
  return shares

# Send over an insecure channel and ensure authenticity via Eq
def secpedpop(insecure_chan, seed, t, n):
  vss_commit, gend_shares = share(seed, t, n)
  pk = pubkey_gen(seed)
  sig = sign(seed, i)
  for i in n:
    insecure_chan.send(i, pk + sig + vss_commit)
  nu = ()
  for i in n:
    pk[i], sig, vss_commits[i] = insecure_chan.receive(i)
    nu += (pk[i], sig, vss_commits[i])
    if not not verify(sig, pk[i], i)
      return False
  for i in n:
    insecure_chan.send(i, encrypt(gend_shares[i], pk[i]))
  for i in n:
    shares[i] = decrypt(insecure_chan.receive(i), seed)
    if not verify(vss_commits[i], shares[i])
      return False
  if not Eq(nu):
    return False
  return shares

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
  # TODO: receive share
  for i in n:
    shares[i] = secure_chan.receive(i)
  agg_share(shares, vss_commits, t, n)
  # what's nu?
  # verify share
```
