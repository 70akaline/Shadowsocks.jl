
module Poly1305

include("uint384.jl")

using .uint384: UInt384, minus, modulo
using ..Common: @lebytes, @little!

@inline function add_poly1305_l(x::UInt384, y::UInt384, z::UInt384)
    z.l = x.l + y.l
    z.m = x.m + y.m + (z.l < y.l ? 0x01 : 0x00)
    z
end

@inline function add_poly1305_m(x::UInt384, y::UInt384, z::UInt384)
    z.m = x.m + y.m
    z.h = x.h + y.h + (z.m < y.m ? 0x01 : 0x00)
    z
end

function multi_poly1305(x::UInt384, y::UInt384, z::UInt384)
    t = UInt128[x.m & 0xffffffffffffffff, x.l >> 64, x.l & 0xffffffffffffffff]
    b = UInt128[y.m & 0xffffffffffffffff, y.l >> 64, y.l & 0xffffffffffffffff]

    z.h = 0x00
    z.m = 0x00

    w = UInt384(0x00)
    @inbounds z.l = t[3] * b[3]

    @inbounds a = t[3] * b[2]
    w.l = a << 64
    w.m = a >> 64
    add_poly1305_l(z, w, z)
    @inbounds a = t[2] * b[3]
    w.l = a << 64
    w.m = a >> 64
    add_poly1305_l(z, w, z)
    w.l = 0

    @inbounds a = t[3] * b[1]
    z.m += a
    z.m < a && z.h + 0x01
    @inbounds a = t[2] * b[2]
    z.m += a
    z.m < a && z.h + 0x01
    @inbounds a = t[1] * b[3]
    z.m += a
    z.m < a && z.h + 0x01

    @inbounds a = t[2] * b[1]
    w.h = a >> 64
    w.m = a << 64
    add_poly1305_m(z, w, z)
    @inbounds a = t[1] * b[2]
    w.h = a >> 64
    w.m = a << 64
    add_poly1305_m(z, w, z)

    z.h += t[1] * b[1]

    z
end

const Poly1305KeyLen = 32
const p = minus(UInt384(0x00, 0x04, 0x00), 0x05)

function Poly1305Cal(r::UInt384, a::UInt384, msg::Vector{UInt8}, isOver::Bool)::UInt384
    len = length(msg)
    nblock = fld(len, 16)
    msgBlock = unsafe_wrap(Array{UInt128}, Ptr{UInt128}(pointer(msg)), nblock)

    t = UInt384(0x00, 0x01, 0x00)
    a = foldl((x, y) -> begin t.l = @little!(y); modulo(multi_poly1305(add_poly1305_l(x, t, x), r, x), p, x) end, msgBlock; init=a)

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

        modulo(multi_poly1305(add_poly1305_l(a, t, a), r, a), p, a)
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
    add_poly1305_l(Poly1305Cal(r, a, msg[end], true), s, a)

    @lebytes(a.l, 16)
end

function Poly1305MAC(msg::Vector{UInt8}, key::Vector{UInt8})::Array{UInt8}
    k = reinterpret(UInt128, key)
    r = UInt384(0x00, 0x00, @little!(k[1]) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = UInt384(0x00, 0x00, @little!(k[2]))

    a = UInt384(0x00)
    add_poly1305_l(Poly1305Cal(r, a, msg, true), s, a)

    @lebytes(a.l, 16)
end

end # module
