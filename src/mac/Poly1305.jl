
module Poly1305

using ..Common

const Poly1305KeyLen = 32
const prefix = BigInt(1) << 128
const p = BigInt(1) << 130 - 5

function Poly1305Cal(r::BigInt, a::BigInt, msg::Vector{UInt8}, isOver::Bool)
    len = length(msg)
    nblock = fld(len, 16)
    msgBlock = unsafe_wrap(Array{UInt128}, Ptr{UInt128}(pointer(msg)), nblock)

    for i in 1:nblock
        a = (a + @inbounds BigInt(Common.little(msgBlock[i])) + prefix) * r % p
    end

    if (local left = len % 16; left != 0)
        block = zeros(UInt8, 16)
        block[1:left] = unsafe_wrap(Array{UInt8}, pointer(msg)+nblock<<4, left)

        a = (a + 
            if isOver
                block[left+1] = 0x01
                BigInt(Common.little(reinterpret(UInt128, block)[]))
            else
                BigInt(Common.little(reinterpret(UInt128, block)[])) + prefix
            end
        ) * r % p
    end

    return a::BigInt
end

function Poly1305MAC(msg::Array{Vector{UInt8}}, key::Vector{UInt8})
    r, s = reinterpret(UInt128, key)
    r = BigInt(Common.little(r) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = BigInt(Common.little(s))

    a = BigInt(0)
    for i in 1:length(msg)-1
        a = Poly1305Cal(r, a, msg[i], false)
    end
    a = Poly1305Cal(r, a, msg[end], true) + s

    return Common.LeBytes(a, 16)::Array{UInt8}
end

function Poly1305MAC(msg::Vector{UInt8}, key::Vector{UInt8})
    r, s = reinterpret(UInt128, key)
    r = BigInt(Common.little(r) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = BigInt(Common.little(s))

    a = BigInt(0)
    a = Poly1305Cal(r, a, msg, true) + s

    return Common.LeBytes(a, 16)::Array{UInt8}
end

end # module
