
module Poly1305

include("uint384.jl")

using .uint384: UInt384, add, minus, multi, modulo
using ..Common: @lebytes, @little!

const Poly1305KeyLen = 32
const p = minus(UInt384(0x00, 0x04, 0x00), 0x05)

function Poly1305Cal(r::UInt384, a::UInt384, msg::Vector{UInt8}, isOver::Bool)::UInt384
    len = length(msg)
    nblock = fld(len, 16)
    msgBlock = unsafe_wrap(Array{UInt128}, Ptr{UInt128}(pointer(msg)), nblock)

    t = UInt384(0x00, 0x01, 0x00)
    a = foldl((x, y) -> begin t.l = @little!(y); modulo(multi(add(x, t, x), r, x), p, x) end, msgBlock; init=a)

    if (local left = len % 16; left != 0)
        block = zeros(UInt8, 16)
        @inbounds block[1:left] = unsafe_wrap(Array{UInt8}, pointer(msg)+nblock*16, left)

        if isOver
            block[left+1] = 0x01
            t.m = 0x00
            t.l = @little!(reinterpret(UInt128, block)[])
        else
            t.l = @little!(reinterpret(UInt128, block)[])
        end

        modulo(multi(add(a, t, a), r, a), p, a)
    end

    a
end

function Poly1305MAC(msg::Array{Vector{UInt8}}, key::Vector{UInt8})::Array{UInt8}
    k = reinterpret(UInt128, key)
    r = UInt384(0x00, 0x00, @little!(k[1]) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = UInt384(0x00, 0x00, @little!(k[2]))

    a = UInt384(0x00)
    @inbounds for i in 1:length(msg)-1
        Poly1305Cal(r, a, msg[i], false)
    end
    add(Poly1305Cal(r, a, msg[end], true), s, a)

    @lebytes(a.l, 16)
end

function Poly1305MAC(msg::Vector{UInt8}, key::Vector{UInt8})::Array{UInt8}
    k = reinterpret(UInt128, key)
    r = UInt384(0x00, 0x00, @little!(k[1]) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = UInt384(0x00, 0x00, @little!(k[2]))

    a = UInt384(0x00)
    add(Poly1305Cal(r, a, msg, true), s, a)

    @lebytes(a.l, 16)
end

end # module
