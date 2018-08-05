
module HKDF

# package code goes here

using SHA

@enum(SHAMETHOD,
    SHA1=0x01,
    SHA2_224=0x02,
    SHA2_256=0x03,
    SHA2_384=0x04,
    SHA2_512=0x05,
    SHA3_224=0x06,
    SHA3_256=0x07,
    SHA3_384=0x08,
    SHA3_512=0x09)

const HMACFUNC = Dict{SHAMETHOD, Function}(
    SHA1::SHAMETHOD => hmac_sha1,
    SHA2_224::SHAMETHOD => hmac_sha2_224,
    SHA2_256::SHAMETHOD => hmac_sha2_256,
    SHA2_384::SHAMETHOD => hmac_sha2_384,
    SHA2_512::SHAMETHOD => hmac_sha2_512,
    SHA3_224::SHAMETHOD => hmac_sha3_224,
    SHA3_256::SHAMETHOD => hmac_sha3_256,
    SHA3_384::SHAMETHOD => hmac_sha3_384,
    SHA3_512::SHAMETHOD => hmac_sha3_512
)

const HASHLEN = Dict{SHAMETHOD, Integer}(
    SHA1::SHAMETHOD => 20,
    SHA2_224::SHAMETHOD => 28,
    SHA2_256::SHAMETHOD => 32,
    SHA2_384::SHAMETHOD => 48,
    SHA2_512::SHAMETHOD => 64,
    SHA3_224::SHAMETHOD => 28,
    SHA3_256::SHAMETHOD => 32,
    SHA3_384::SHAMETHOD => 48,
    SHA3_512::SHAMETHOD => 64
)

function hashType(t::String)
    return eval(Symbol(UInt8('-') in Vector{UInt8}(t) ? replace(t, r"(?<sha>\w+)(?<s>[-])(?<num>\w+)", s"\1_\3") : t))
end

function hkdf(sha::SHAMETHOD, salt::Vector{UInt8}, ikm::Vector{UInt8}, info::Vector{UInt8}, keylen::Integer)
    prk, err = HKDF_Extract(sha, salt, ikm)
    if err != nothing
        return err
    end

    return HKDF_Expand(sha, prk, info, keylen)
end
hkdf(sha::AbstractString, salt::Vector{UInt8}, ikm::Vector{UInt8}, info::Vector{UInt8}, keylen::Integer) = hkdf(hashType(sha)::SHAMETHOD, salt::Vector{UInt8}, ikm::Vector{UInt8}, info::Vector{UInt8}, keylen::Integer)

function HKDF_Extract(sha::SHAMETHOD, salt::Vector{UInt8}, ikm::Vector{UInt8})
    prk = try
        HMACFUNC[sha::SHAMETHOD](salt, ikm)
    catch err 
        return nothing, err
    end

    return prk, nothing
end

function HKDF_Expand(sha::SHAMETHOD, prk::Vector{UInt8}, info::Vector{UInt8}, keylen::Integer)
    hashlen = HASHLEN[sha::SHAMETHOD]
    n = UInt8(ceil(keylen/hashlen))
    key = Vector{UInt8}(n * hashlen)

    T = UInt8[]
    for i in 0x01:n
        T = HMACFUNC[sha::SHAMETHOD](prk, [T; info; i])
        key[(i-1)*hashlen + 1 : i * hashlen] = T
    end

    return key[1:keylen]
end

end # module
