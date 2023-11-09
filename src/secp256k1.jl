const SECP256K1_CONTEXT_NONE::UInt32 = 1 << 0

const SECP256K1_FLAGS_TYPE_COMPRESSION::UInt32 = 1 << 1
const SECP256K1_FLAGS_BIT_COMPRESSION::UInt32 = 1 << 8
const SECP256K1_EC_COMPRESSED::UInt32 = SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION
const SECP256K1_EC_UNCOMPRESSED::UInt32 = SECP256K1_FLAGS_TYPE_COMPRESSION

# # SECP256K1_FE = Tuple{NTuple{10, UInt32}, Int32, Int32} # with SECP256K1_FE_VERIFY_FIELDS
# SECP256K1_FE = Tuple{NTuple{10, UInt32}} # without SECP256K1_FE_VERIFY_FIELDS
# SECP256K1_SCALAR = NTuple{4, UInt64}
# SECP256K1_GEJ = Tuple{SECP256K1_FE, SECP256K1_FE, SECP256K1_FE, Int32}
# SECP256K1_ECMULT_GEN_CONTEXT = Tuple{Int32, SECP256K1_SCALAR, SECP256K1_GEJ}
# SECP256K1_CALLBACK = Tuple{Ptr{Cvoid}, Ptr{Cvoid}}
# SECP256K1_CONTEXT = Tuple{SECP256K1_ECMULT_GEN_CONTEXT, SECP256K1_CALLBACK, SECP256K1_CALLBACK, Int32}

if Sys.isapple()
    const libsecp256k1_fn = joinpath(pwd(), "lib/libsecp256k1.dylib")
elseif Sys.islinux()
    const libsecp256k1_fn::String = joinpath(pwd(), "lib/libsecp256k1.so")
elseif Sys.iswindows()
    throw("Not implemented (libsecp256k1)")
end

function secp256k1_context_create()::Ptr{Any}
    return ccall((:secp256k1_context_create, libsecp256k1_fn), Ptr{Any}, (UInt32,), SECP256K1_CONTEXT_NONE)
end

function secp256k1_ec_pubkey_create(context::Ptr{Any}, private_key::Vector{UInt8})::Vector{UInt8}
    public_key = Array{UInt8}(undef, 64)
    ccall((:secp256k1_ec_pubkey_create, libsecp256k1_fn), 
          Int32, 
          (Ref{Any}, Ref{UInt8}, Ref{UInt8}), 
          context, public_key, private_key)
    return public_key
end

function secp256k1_ec_pubkey_serialize(context::Ptr{Any}, 
                                       unserialize_public_key::Vector{UInt8}; 
                                       compressed::Bool=true)::Vector{UInt8}
        
        output_size::Csize_t = 0
        if compressed
            public_key = Array{UInt8}(undef, 33)
            output_size = 33
        else
            public_key = Array{UInt8}(undef, 65)
            output_size = 65
        end
        
        ccall((:secp256k1_ec_pubkey_serialize, libsecp256k1_fn), 
        Int32, 
        (Ref{Any}, Ref{Cuchar}, Ref{Csize_t}, Ref{UInt8}, UInt32),
        context, public_key, Ref(output_size), unserialize_public_key, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)
        
        return public_key
end

function secp256k1_context_destroy(context::Ptr{Any})::Cvoid
    return ccall((:secp256k1_context_destroy, libsecp256k1_fn), Cvoid, (Ref{Any},), context)
end
