const max_bigint_privkey::BigInt = 115792089237316195423570985008687907852837564279074904382605163141518161494336
const max_privkey::Vector{UInt8} = bytes(max_bigint_privkey)
const min_privkey = vcat(zeros(UInt8, 31), 0x01)

struct PrivateKey
    key::Vector{UInt8}
    wif::String
    wif_c::String
end

struct PublicKey
    key::Vector{UInt8}
    key_hash::Vector{UInt8}
    key_c::Vector{UInt8}
    key_c_hash::Vector{UInt8}
end

struct BTCAddresses
    p2pkh::String
    p2pkh_c::String
    p2sh_c::String
    p2wpkh::String
end

struct Wallet
    private_key::PrivateKey
    public_key::PublicKey
    addresses::BTCAddresses
end

function Base.show(io::IO, private_key::PrivateKey)
    println(io, "PrivateKey")
    println(io, "     key: $(bytes2hex(private_key.key))")
    println(io, "     WIF: $(private_key.wif)")
    print(io, "  WIF(c): $(private_key.wif_c)")
end

function Base.show(io::IO, public_key::PublicKey)
    println(io, "PublicKey")
    println(io, "             key: $(bytes2hex(public_key.key))")
    println(io, "     rmd160 hash: $(bytes2hex(public_key.key_hash))")
    println(io, "          key(c): $(bytes2hex(public_key.key_c))")
    print(io,   "  rmd160 hash(c): $(bytes2hex(public_key.key_c_hash))")
end

function Base.show(io::IO, addrs::BTCAddresses)
    println(io, "BTCAddresses")
    println(io, "   P2PKH(c) address: $(addrs.p2pkh_c)")
    println(io, "      P2PKH address: $(addrs.p2pkh)")
    println(io, "    P2SH(c) address: $(addrs.p2sh_c)")
    print(io,   "     P2WPKH address: $(addrs.p2wpkh)")
end

function Base.show(io::IO, wallet::Wallet)
    println(io, "Wallet")
    println(io, wallet.private_key)
    println(io)
    println(io, wallet.public_key)
    println(io)
    print(io, wallet.addresses)
end

"""
    function PrivateKey(private_key::T) where {T <: Integer}

Assumes `private_key` is an integer and pass it as its bytes representation.

"""
function PrivateKey(private_key::T) where {T <: Integer}
    return PrivateKey(bytes(private_key))
end

"""
    function PrivateKey(private_key::AbstractString)

If `length(private_key)` = 51 or 52, `private_key` is assumed to be in WIF uncompressed or compressed format

If `length(private_key)` = 64, `private_key` is assumed to be a string of hexadecimal numbers
"""
function PrivateKey(private_key::AbstractString; check=true)
    check && (length(private_key) in (51, 52, 64) || throw(ArgumentError("Private key must either be 51 (WIF), 52 (compressed WIF), or 64 characters long but length(private_key) = $(length(private_key))")))
    
    if length(private_key) in (51, 52)
        return PrivateKey(wif_to_privatekey_bytes(private_key), check=check)
    else
        private_key = hex2bytes(private_key)
        length(private_key) < 32 && prepend!(private_key, fill(0x00, 32 - length(private_key)))
        return PrivateKey(private_key, check=check)
    end
end


"""
    function PrivateKey(private_key::AbstractVector{UInt8}; check=true, pad=:left, padvalue=0x00)

Return PrivateKey given a `private_key` in its bytes representation.

## Arguments
- `check=true`: Perform basic sanity check on key (length and range)
- `pad=:left`: Pad bytes array to the `:left` or to the `:right` with `padvalue` to make it 32-bytes long
- `padvalue=0x00`: Padding byte
"""
function PrivateKey(private_key::AbstractVector{UInt8}; check=true, pad=:left, padvalue=0x00)
    if length(private_key) < 32
        if pad == :left
            private_key = vcat(fill(padvalue, 32 - length(private_key)), private_key)
        elseif pad == :right
            private_key = vcat(private_key, fill(padvalue, 32 - length(private_key)))
        end
    end
    if check
        length(private_key) == 32 || throw(ArgumentError("Private key must be 32 bytes long but length(private_key) = $(length(private_key))"))
        (1 <= to_big(private_key) <= 115792089237316195423570985008687907852837564279074904382605163141518161494336) || throw("Private key out of range")
    end
    return PrivateKey(private_key, 
                      privatekey_to_wif(private_key, compressed=false),
                      privatekey_to_wif(private_key, compressed=true))
end

function PublicKey(private_key::Union{AbstractString, AbstractVector{UInt8}, T}; check=true) where {T <: Integer}
    return PublicKey(PrivateKey(private_key, check=check))
end

function PublicKey_slow(private_key::PrivateKey; hash160=true)

    big_pk =  to_big(private_key.key)
    point = big_pk * G

    xbytes = bytes(point.𝑥.𝑛)
    prepend!(xbytes, fill(0x00, 32 - length(xbytes)))
    ybytes = bytes(point.𝑦.𝑛)
    prepend!(ybytes, fill(0x00, 32 - length(ybytes)))

    public_key = vcat(0x04, xbytes, ybytes)
    public_key_c = vcat(mod(point.𝑦.𝑛, 2) == 0 ? 0x02 : 0x03, xbytes)

    if hash160
        return PublicKey(public_key, ripemd160(sha256(public_key)), 
                         public_key_c, ripemd160(sha256(public_key_c)))
    else
        return PublicKey(public_key, UInt8[], public_key_c, UInt8[])
    end
end

function PublicKey(private_key::PrivateKey; hash160=true)

    ctx = secp256k1_context_create()
    unserialized_pubkey = secp256k1_ec_pubkey_create(ctx, private_key.key)
    public_key = secp256k1_ec_pubkey_serialize(ctx, unserialized_pubkey, compressed=false)
    public_key_c = secp256k1_ec_pubkey_serialize(ctx, unserialized_pubkey, compressed=true)
    secp256k1_context_destroy(ctx)

    if hash160
        return PublicKey(public_key, ripemd160(sha256(public_key)), 
                         public_key_c, ripemd160(sha256(public_key_c)))
    else
        return PublicKey(public_key, UInt8[], public_key_c, UInt8[])
    end
end

function BTCAddresses(private_key::PrivateKey; testnet=false)
    return BTCAddresses(PublicKey(private_key), testnet=testnet)
end

function BTCAddresses(private_key::Union{AbstractString, AbstractVector{UInt8}, T}; testnet=false) where {T <: Integer}
    return BTCAddresses(PrivateKey(private_key), testnet=testnet)
end

function hash_to_p2pkh(hash::AbstractVector{UInt8}; testnet=false)::String
    padded_hash = vcat(testnet ? 0x6f : 0x00, hash)
    checksum = sha256(sha256(padded_hash))[1:4]
    return String(base58encode(vcat(padded_hash, checksum)))
end

function hash160_to_p2sh(hash::Vector{UInt8}; testnet=false)::String
    # P2SH-P2WPKH (https://bitcointalk.org/index.php?topic=5229211.0)
    redeem_script = vcat([0x00, 0x14], hash)
    p2sh_address_raw = vcat(testnet ? 0xc4 : 0x05, ripemd160(sha256(redeem_script)))
    p2sh_address = base58encode(vcat(p2sh_address_raw, sha256(sha256(p2sh_address_raw))[1:4]))
    return String(p2sh_address)
end

function scripthash_to_p2sh(hash::Vector{UInt8}; testnet=false)::String
    p2sh_address_raw = vcat(testnet ? 0xc4 : 0x05, hash)
    p2sh_address = base58encode(vcat(p2sh_address_raw, sha256(sha256(p2sh_address_raw))[1:4]))
    return String(p2sh_address)
end

function hash160_to_p2wpkh(hash::Vector{UInt8}; testnet=false)::String
    # P2WPKH (https://bitcointalk.org/index.php?topic=4992632.0)
    versioned_squashed = vcat(0x00, squash_8to5(hash))
    p2wpkh_address = bech32_encode(testnet ? "tb" : "bc", versioned_squashed)
    return p2wpkh_address
end

function BTCAddresses(public_key::PublicKey; testnet=false)

    p2pkh_address = hash_to_p2pkh(public_key.key_hash, testnet=testnet)

    compressed_p2pkh_address = hash_to_p2pkh(public_key.key_c_hash, testnet=testnet)

    p2sh_address = hash160_to_p2sh(public_key.key_c_hash, testnet=testnet)
    p2wpkh_address = hash160_to_p2wpkh(public_key.key_c_hash, testnet=testnet)

    return BTCAddresses(p2pkh_address, compressed_p2pkh_address, p2sh_address, p2wpkh_address)
end

function Wallet(private_key::Union{AbstractString, AbstractVector{UInt8}, T}) where {T <: Integer}
    return Wallet(PrivateKey(private_key))
end

function Wallet(private_key::PrivateKey)
    public_key = PublicKey(private_key)
    return Wallet(deepcopy(private_key), public_key, BTCAddresses(public_key))
end

function privatekey_to_wif(private_key::AbstractString; compressed=true, check=true)::String
    check && validate_private_key(private_key)
    return privatekey_to_wif(hex2bytes(private_key), compressed=compressed, check=false)
end

function privatekey_to_wif(private_key::AbstractVector{UInt8}; compressed=true, check=true)::String
    check && validate_private_key(private_key)
    fullkey = vcat(0x80, private_key)
    compressed && push!(fullkey, 0x01)
    checksum = sha256(sha256(fullkey))[1:4]
    wif = base58encode(vcat(fullkey, checksum))
    return String(wif)
end

function wif_to_privatekey_bytes(wif::AbstractString)::Vector{UInt8}
    length(wif) in (51, 52) || throw(ArgumentError("WIF strings must be 51 (uncompressed) or 52 (compressed) characters long"))
    decoded_wif = base58decode(codeunits(wif))
    checksum = decoded_wif[end-3:end]
    sha256(sha256(decoded_wif[1:end-4]))[1:4] == checksum || throw("Checksum error")
    if length(wif) == 52 # WIF compressed
        return decoded_wif[2:end-5]
    elseif length(wif) == 51 # WIF uncompressed
        return decoded_wif[2:end-4]
    end
end

# Stripped down version for puzzles, no private key check
# function privatekey_to_p2pkhc(private_key::AbstractString; testnet=testnet)::Vector{UInt8}
#     return privatekey_to_p2pkhc(hex2bytes(private_key), testnet=testnet)
# end

# function privatekey_to_p2pkhc(private_key::Vector{UInt8}; testnet=false)::Vector{UInt8}
#     point = to_big(private_key) * G
#     xbytes = bytes(point.𝑥.𝑛)
#     length(xbytes) < 32 && prepend!(xbytes, fill(0x00, 32 - length(xbytes)))
#     public_key_c = vcat(mod(point.𝑦.𝑛, 2) == 0 ? 0x02 : 0x03, xbytes)
#     public_key_c_hash = ripemd160(sha256(public_key_c))
#     return hash_to_p2pkh(public_key_c_hash, testnet=testnet)
# end


function validate_private_key(private_key::AbstractVector{UInt8})
    length(private_key) == 32 || throw(ArgumentError("Private key must be 32 bytes long but length(private_key) = $(length(private_key))"))
    return validate_private_key(to_big(private_key))
end

function validate_private_key(private_key::T; throw_error=true) where {T <: Integer}
    if 1 <= private_key <= max_bigint_privkey
        return true
    else
        if throw_error
            throw("Private key out of range")
        else
            return false
        end
    end
end