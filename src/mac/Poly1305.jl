
module Poly1305

using ..Common: @lebytes, @little!

const Poly1305KeyLen = 32
const prefix = BigInt(1) << 128
const p = BigInt(1) << 130 - 5

function Poly1305Cal(r::BigInt, a::BigInt, msg::Vector{UInt8}, isOver::Bool)::BigInt
    len = length(msg)
    nblock = fld(len, 16)
    msgBlock = unsafe_wrap(Array{UInt128}, Ptr{UInt128}(pointer(msg)), nblock)

    a = foldl((x, y) -> (x + @little!(y) + prefix) * r % p, msgBlock; init=a)

    if (local left = len % 16; left != 0)
        block = zeros(UInt8, 16)
        block[1:left] = unsafe_wrap(Array{UInt8}, pointer(msg)+nblock<<4, left)

        a = (a + 
            if isOver
                block[left+1] = 0x01
                @little!(reinterpret(UInt128, block)[])
            else
                @little!(reinterpret(UInt128, block)[]) + prefix
            end
        ) * r % p
    end

    return a
end

function Poly1305MAC(msg::Array{Vector{UInt8}}, key::Vector{UInt8})::Array{UInt8}
    r, s = reinterpret(UInt128, key)
    r = BigInt(@little!(r) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = BigInt(@little!(s))

    a = BigInt(0)
    for i in 1:length(msg)-1
        a = Poly1305Cal(r, a, msg[i], false)
    end
    a = Poly1305Cal(r, a, msg[end], true) + s

    return @lebytes(a, 16)
end

function Poly1305MAC(msg::Vector{UInt8}, key::Vector{UInt8})::Array{UInt8}
    r, s = reinterpret(UInt128, key)
    r = BigInt(@little!(r) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = BigInt(@little!(s))

    a = BigInt(0)
    a = Poly1305Cal(r, a, msg, true) + s

    return @lebytes(a, 16)
end

end # module
