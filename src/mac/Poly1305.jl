
module Poly1305

include("uint384.jl")

using .uint384: UInt384, minus, and
using ..Common: @little!, @LittleEndianBytes

@inline function add_poly1305_l(x::UInt384, y::UInt384, z::UInt384)
    z.l = x.l + y.l
    z.m = z.l < y.l ? x.m + y.m + 0x01 : x.m + y.m
    z
end

@inline function add_poly1305_m(x::UInt384, y::UInt384, z::UInt384)
    z.m = x.m + y.m
    z.h = z.m < y.m ? x.h + y.h + 0x01 : x.h + y.h
    z
end

function multi_poly1305(x::UInt384, y::UInt384, z::UInt384)
    t = UInt128[x.m, x.l >> 64, x.l & 0xffffffffffffffff]
    b = UInt128[y.m, y.l >> 64, y.l & 0xffffffffffffffff]

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
    z.m < a && (z.h += 0x01)
    @inbounds a = t[2] * b[2]
    z.m += a
    z.m < a && (z.h += 0x01)
    @inbounds a = t[1] * b[3]
    z.m += a
    z.m < a && (z.h += 0x01)

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

const n = UInt384(0x00, 0x04, 0x00)
const m = UInt384(0x00, 0x03, typemax(UInt128))
const o = UInt384(0x00, 0x00, 0x05)

@inline function shiftright_poly1305_130(x::UInt384)
    x.l = x.m >> 0x02 | x.h << 0x007e
    x.m = x.h >> 0x02
    x.h = 0x00
    x
end

@inline function shiftleft_poly1305_2(x::UInt384)
    x.h = x.h << 0x02 | x.m >> 0x7e
    x.m = x.m << 0x02 | x.l >> 0x7e
    x.l = x.l << 0x02
    x
end

@inline function multi_poly1305_0x05(x::UInt384)
    add_poly1305_l(x, shiftleft_poly1305_2(UInt384(x.h, x.m, x.l)), x)
    x
end

@inline function modulo_poly1305_p(x::UInt384)
    while uint384.more(x, n)
        z = UInt384(x.h, x.m, x.l)
        w = UInt384(x.h, x.m, x.l)

        shiftright_poly1305_130(z)
        multi_poly1305_0x05(z)

        uint384.and(w, m, w)

        add_poly1305_l(z, w, x)
    end

    if !(uint384.less(x, p))
        uint384.minus(x, p, x)
    end

    x
end

const Poly1305KeyLen = 32
const p = UInt384(
    0x00000000000000000000000000000000, 
    0x00000000000000000000000000000003, 
    0xfffffffffffffffffffffffffffffffb
)

function Poly1305Cal(r::UInt384, a::UInt384, msg::Vector{UInt8}, isOver::Bool)::UInt384
    len = length(msg)
    nblock = fld(len, 16)
    msgBlock = unsafe_wrap(Array{UInt128}, Ptr{UInt128}(pointer(msg)), nblock)

    t = UInt384(0x00, 0x01, 0x00)
    a = foldl((x, y) -> begin t.l = @little!(y); modulo_poly1305_p(multi_poly1305(add_poly1305_l(x, t, x), r, x)) end, msgBlock; init=a)

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

        modulo_poly1305_p(multi_poly1305(add_poly1305_l(a, t, a), r, a))
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

    @LittleEndianBytes(a.l)
end

function Poly1305MAC(msg::Vector{UInt8}, key::Vector{UInt8})::Array{UInt8}
    k = reinterpret(UInt128, key)
    r = UInt384(0x00, 0x00, @little!(k[1]) & 0x0ffffffc0ffffffc0ffffffc0fffffff)
    s = UInt384(0x00, 0x00, @little!(k[2]))

    a = UInt384(0x00)
    add_poly1305_l(Poly1305Cal(r, a, msg, true), s, a)

    @LittleEndianBytes(a.l)
end

end # module

false && begin

function modulo250(x)
    while x > 256
        x = (x >> 8) * 6 + x & 0xff
    end

    if x >= 250
        x = x - 250
    end

    x
end

const p1 = Shadowsocks.Crypto.Poly1305.minus(Shadowsocks.Crypto.Poly1305.UInt384(0x00, 0x04, 0x00), 0x05)

for i in 1:10
    a, b, c = UInt128(0), rand(UInt128), rand(UInt128);
    x = Shadowsocks.Crypto.Poly1305.UInt384(a, b, c);
    y = Shadowsocks.Crypto.Poly1305.UInt384(a, b, c);
    Shadowsocks.Crypto.Poly1305.modulo_poly1305_p(x)
    Shadowsocks.Crypto.Poly1305.modulo(y, p1, y)
end

end
