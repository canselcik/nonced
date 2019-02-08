# nonced
Private Key Recovery in Case of Nonce Reuse

- Extracts `PubKey(integerOrder(G))`, `Signature(r, s)` from inputs of transactions
- Derives private key and K value that was used to sign two inputs in case pubkey and R values have been reused. 

```
pk = Private Key (unknown at first)
K  = K value that was used (unknown at first)
N  = integer order of G (part of public key, known)
```

```
# From Signing Defintion
s1 = (L1 + pk * R) / K Mod N    and     s2 = (L2 + pk * R) / K Mod N

# Rearrange
K = (L1 + pk * R) / s1 Mod N    and     K = (L2 + pk * R) / s2 Mod N

# Set Equal
(L1 + pk * R) / s1 = (L2 + pk * R) / s2     Mod N

# Solve for pk (private key)
pk Mod N = (s2 * L1 - s1 * L2) / R * (s1 - s2)
pk Mod N = (s2 * L1 - s1 * L2) * (R * (s1 - s2)) ** -1
```
