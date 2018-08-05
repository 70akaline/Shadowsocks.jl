
module Poly1305

# ========Poly1305============

function LeBytes(num::BigInt, n::Integer)
    x = Vector{UInt8}(n)

    for i in 1:n
        x[i] = UInt8((num >> ((i-1) * 8)) & 0xff)
    end

    return x
end

const Poly1305KeyLen = 32

function Poly1305Cal(r::BigInt, a::BigInt, p::BigInt, msg::Vector{UInt8}, isover::Bool)
    len = length(msg)
    nblock = Integer(floor(len/16))
    ptr = Ptr{UInt128}(pointer(msg))

    for i in 1:nblock
        n = BigInt(ltoh(unsafe_load(ptr, i))) + BigInt(1) << 128
        a = (a + n) * r % p
    end

    left = len % 16

    if left != 0
        block = zeros(UInt8, 16)
        block[1:left] = msg[nblock << 4 + 1 : nblock << 4 + left]

        if isover
            block[left+1] = 0x01
            n = BigInt(ltoh(unsafe_load(Ptr{UInt128}(pointer(block)))))
        else
            n = BigInt(ltoh(unsafe_load(Ptr{UInt128}(pointer(block))))) + BigInt(1) << 128
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
    p = BigInt(1) << 130 - 5

    a = BigInt(0)

    if msg isa Vector{UInt8}
        a = Poly1305Cal(r, a, p, msg, true) + s
    elseif msg isa Array{Vector{UInt8}}
        for i in 1:length(msg)-1
            a = Poly1305Cal(r, a, p, msg[i], false)
        end
        a = Poly1305Cal(r, a, p, msg[end], true) + s
    end

    return LeBytes(a, 16)
end

end # end module
