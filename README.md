# NaiveBTC

Extremely naive Bitcoin keys and addresses generator. Not intended for any kind of serious use whatsoever. Came out of a weekend attempt to understand the key and address formats of the Bitcoin protocol.

```
julia> using NaiveBTC

julia> Wallet("cafebabe"^8)

Wallet

PrivateKey
     key: cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe
     WIF: 5KMgpMb55rwuL7WdkNrRNh5MYTB9EsKke3de9XC856DTJ3SNSFg
  WIF(c): L42Jk1sP2TTKyMjoCTT8ajtDfpXmND7mcWcixcG6D41y3kockVEu

PublicKey
             key: 04672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a32e02c7f93d13dc2732b760ca377a5897b9dd41a1c1b29dc0442fdce6d0a04d1d
     rmd160 hash: 848e28f24b9865075f6e6efa3abbc5736e23b261
          key(c): 03672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3
  rmd160 hash(c): d88306005f88e2f485f0b36cbbbc19a4690a6937

BTCAddresses
   P2PKH(c) address: 1Ljov72Bymu55PFahaptQnHxy9yKg5PSQG
      P2PKH address: 1D5tVmYEZsr8VBmCnfDcuG2cSPJ5Vzmubd
    P2SH(c) address: 3ChuD9eXvaCa8ZY1Pt6W5mSDpfBVLc11Vt
  BECH32(c) address: bc1qmzpsvqzl3r30fp0skdkth0qe535s56fhf8v4ws
```
We check against [PrivateKeyFinder.io](https://privatekeyfinder.io/key/cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe) and everything appears to be in order.