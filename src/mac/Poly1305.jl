
module Poly1305

function LeBytes(num::BigInt, n::Integer)
    x = Vector{UInt8}(undef, n)

    for i in 1:n
        x[i] = UInt8((num >> ((i-1) << 3)) & 0xff)
    end

    return x
end

const Poly1305KeyLen = 32
const prefix = BigInt(1) << 128
const p = BigInt(1) << 130 - 5

function Poly1305Cal(r::BigInt, a::BigInt, msg::Vector{UInt8}, isover::Bool)
    len = length(msg)
    nblock = Integer(floor(len/16))
    msgBlock = unsafe_wrap(Array{UInt128}, Ptr{UInt128}(pointer(msg)), nblock)

    for i in 1:nblock
        n = BigInt(ltoh(msgBlock[i])) + prefix

        a = (a + n) * r % p
    end
    left = len % 16

    if left != 0
        block = zeros(UInt8, 16)
        block[1:left] = msg[nblock << 4 + 1 : nblock << 4 + left]

        if isover
            block[left+1] = 0x01
            n = BigInt(ltoh(reinterpret(UInt128, block)[]))
        else
            n = BigInt(ltoh(reinterpret(UInt128, block)[])) + prefix
        end

        a = (r * (a + n)) % p
    end

    return a
end

function Poly1305MAC(msg::Union{Vector{UInt8}, Array{Vector{UInt8}}}, key::Vector{UInt8})
    if length(key) != Poly1305KeyLen
        return nothing
    end

    r, s = reinterpret(UInt128, key)
    r = BigInt(ltoh(r) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = BigInt(ltoh(s))

    a = BigInt(0)

    if msg isa Vector{UInt8}
        a = Poly1305Cal(r, a, msg, true) + s
    elseif msg isa Array{Vector{UInt8}}
        for i in 1:length(msg)-1
            a = Poly1305Cal(r, a, msg[i], false)
        end
        a = Poly1305Cal(r, a, msg[end], true) + s
    end

    return LeBytes(a, 16)
end

end # module
