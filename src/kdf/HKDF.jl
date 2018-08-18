
module HKDF

using SHA

const HMACFUNC = Dict{AbstractString, Function}(
    "SHA1" => hmac_sha1,
    "SHA2-224" => hmac_sha2_224,
    "SHA2-256" => hmac_sha2_256,
    "SHA2-384" => hmac_sha2_384,
    "SHA2-512" => hmac_sha2_512,
    "SHA3-224" => hmac_sha3_224,
    "SHA3-256" => hmac_sha3_256,
    "SHA3-384" => hmac_sha3_384,
    "SHA3-512" => hmac_sha3_512
)

const HASHLEN = Dict{AbstractString, Integer}(
    "SHA1" => 20,
    "SHA2-224" => 28,
    "SHA2-256" => 32,
    "SHA2-384" => 48,
    "SHA2-512" => 64,
    "SHA3-224" => 28,
    "SHA3-256" => 32,
    "SHA3-384" => 48,
    "SHA3-512" => 64
)

function hkdf(sha::AbstractString, salt::Vector{UInt8}, ikm::Vector{UInt8}, info::Vector{UInt8}, keylen::Integer)
    prk, err = HKDF_Extract(sha, salt, ikm)
    if err != nothing
        return nothing, err
    end
    
    okm, err = HKDF_Expand(sha, prk, info, keylen)
    if err != nothing
        return nothing, err
    end

    return okm, nothing
end

function HKDF_Extract(sha::AbstractString, salt::Vector{UInt8}, ikm::Vector{UInt8})
    prk = try
        HMACFUNC[sha](salt, ikm)
    catch err 
        return nothing, err
    end

    return prk, nothing
end

function HKDF_Expand(sha::AbstractString, prk::Vector{UInt8}, info::Vector{UInt8}, keylen::Integer)
    hashlen = HASHLEN[sha]
    n = UInt8(cld(keylen, hashlen))
    left = keylen % hashlen
    key = Vector{UInt8}(undef, n * hashlen + left)

    T = UInt8[]
    for i in 0x01:n
        T = HMACFUNC[sha](prk, [T; info; i])
        key[(i-1) * hashlen + 1 : i * hashlen] = T
    end

    left != 0 && begin key[n * hashlen + 1 : n * hashlen + left] = HMACFUNC[sha](prk, [T; info; n])[1 : left] end

    return key, nothing
end

end # module
