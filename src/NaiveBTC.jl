module NaiveBTC

using SHA
using Base58
using Ripemd
using BitConverter
using DelimitedFiles
import Base: show

using ECC: G

include("bech32.jl")

export secp256k1_context_create, secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_serialize, secp256k1_context_destroy
include("secp256k1.jl")

export PrivateKey, PublicKey, BTCAddresses, Wallet
export wif_to_privatekey_bytes, validate_private_key
export hash_to_p2pkh, hash160_to_p2sh, hash160_to_p2wpkh
include("addresses.jl")

export brainwallet, read_balance_dict, check_balance
include("helpers.jl")

export opcodes_dict
include("opcodes.jl")

end
