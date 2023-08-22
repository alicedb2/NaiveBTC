module NaiveBTC

using SHA
using Base58
using Ripemd
using BitConverter
using ECC: G

import Base: show

include("bech32.jl")

export PrivateKey, PublicKey, BTCAddresses, Wallet
include("addresses.jl")

end
