
module uint384

mutable struct UInt384
    h::UInt128
    m::UInt128
    l::UInt128
end
UInt384(x::Integer) = UInt384(0x00, 0x00, x)

function shiftleft(x::UInt384, n::UInt16)
    if n < 0x80 # 128
        x.h = x.h << n | x.m >> (0x80-n)
        x.m = x.m << n | x.l >> (0x80-n)
        x.l = x.l << n
    elseif n == 0x80
        x.h = x.m
        x.m = x.l
        x.l = 0x00
    elseif n < 0x0100 # 256
        x.h = x.m << (n-0x80) | x.l >> (0x0100-n)
        x.m = x.l << (n-0x80)
        x.l = 0x00
    elseif n == 0x0100
        x.h = x.l
        x.m = 0x00
        x.l = 0x00
    elseif n < 0x0180 # 384
        x.h = x.l << (n-0x0100)
        x.m = 0x00
        x.l = 0x00
    else
        x.h = 0x00
        x.m = 0x00
        x.l = 0x00
    end
    x
end

function shiftright(x::UInt384, n::UInt16)
    if n < 0x80 # 128
        x.l = x.l >> n | x.m << (0x80-n)
        x.m = x.h << (0x80-n) | x.m >> n
        x.h = x.h >> n
    elseif n == 0x80
        x.l = x.m
        x.m = x.h
        x.h = 0x00
    elseif n < 0x0100 # 256
        x.l = x.m >> (n-0x80) | x.h << (0x0100-n)
        x.m = x.h >> (n-0x80)
        x.h = 0x00
    elseif n == 0x0100
        x.l = x.h
        x.m = 0x00
        x.h = 0x00
    elseif n < 0x0180 # 384
        x.l = x.h >> (n-0x0100)
        x.m = 0x00
        x.h = 0x00
    else
        x.l = 0x00
        x.m = 0x00
        x.h = 0x00
    end
    x
end

function or(x::UInt384, y::UInt384, z::UInt384)
    z.h = x.h | y.h
    z.m = x.m | y.m
    z.l = x.l | y.l
    z
end

function and(x::UInt384, y::UInt384, z::UInt384)
    z.h = x.h & y.h
    z.m = x.m & y.m
    z.l = x.l & y.l
    z
end

function less(x::UInt384, y::UInt384)
    if x.h == y.h
        if x.m == y.m 
            x.l < y.l 
        else
            x.m < y.m
        end
    else
        x.h < y.h
    end
end

function more(x::UInt384, y::UInt384)
    if x.h == y.h
        if x.m == y.m
            x.l > y.l
        else
            x.m > y.m
        end
    else
        x.h > y.h
    end
end

function bits(x::UInt384)
    if x.h > 0x00
        c = 0x0100
        t = x.h
        while t > 0x00
            t >>= 0x01
            c += 0x01
        end
    elseif x.m > 0x00
        c = 0x0080
        t = x.m
        while t > 0x00
            t >>= 0x01
            c += 0x01
        end
    else
        c = 0x0000
        t = x.l
        while t > 0x00
            t >>= 0x01
            c += 0x01
        end
    end
    c
end

function add(x::UInt384, y::UInt384, z::UInt384)
    a = x.l
    b = x.m
    z.l = x.l + y.l
    z.m = x.m + y.m + (z.l < a ? 0x01 : 0x00)
    z.h = x.h + y.h + (z.m < b ? 0x01 : 0x00)
    z
end

function minus(x::UInt384, y::UInt384, z::UInt384)
    a = x.l
    b = x.m
    z.l = x.l - y.l
    z.m = x.m - y.m - (z.l > a ? 0x01 : 0x00)
    z.h = x.h - y.h - (z.m > b ? 0x01 : 0x00)
    z
end

function minus(x::UInt384, y::Integer)
    z = UInt384(0)
    minus(x, UInt384(y), z)
    z
end

function multi(x::UInt384, y::UInt384, z::UInt384) # only use 320 bits
    t = UInt128[x.h & 0xffffffffffffffff, x.m >> 64, x.m & 0xffffffffffffffff, x.l >> 64, x.l & 0xffffffffffffffff]
    b = UInt128[y.h & 0xffffffffffffffff, y.m >> 64, y.m & 0xffffffffffffffff, y.l >> 64, y.l & 0xffffffffffffffff]

    z.h = 0
    z.m = 0

    w = UInt384(0)
    z.l = t[5] * b[5]

    a = t[5] * b[4]
    w.l = a << 64
    w.m = a >> 64
    add(z, w, z)
    a = t[4] * b[5]
    w.l = a << 64
    w.m = a >> 64
    add(z, w, z)
    w.l = 0
    w.m = 0

    w.m = t[5] * b[3]
    add(z, w, z)
    w.m = t[4] * b[4]
    add(z, w, z)
    w.m = t[3] * b[5]
    add(z, w, z)
    w.m = 0

    a = t[5] * b[2]
    w.h = a >> 64
    w.m = a << 64
    add(z, w, z)
    a = t[4] * b[3]
    w.h = a >> 64
    w.m = a << 64
    add(z, w, z)
    a = t[3] * b[4]
    w.h = a >> 64
    w.m = a << 64
    add(z, w, z)
    a = t[2] * b[5]
    w.h = a >> 64
    w.m = a << 64
    add(z, w, z)
    w.h = 0
    w.m = 0

    w.h = t[5] * b[1]
    add(z, w, z)
    w.h = t[4] * b[2]
    add(z, w, z)
    w.h = t[3] * b[3]
    add(z, w, z)
    w.h = t[2] * b[4]
    add(z, w, z)
    w.h = t[1] * b[5]
    add(z, w, z)
    w.h = 0

    z
end

function modulo(x::UInt384, y::UInt384, w::UInt384)
    w.h = x.h
    w.m = x.m
    w.l = x.l
    if more(y, x)
        w
    else
        c = shiftleft(UInt384(y.h, y.m, y.l), bits(x) - bits(y))
        while less(y, w)
            if less(c, w)
                minus(w, c, w)
            end
            shiftright(c, 0x0001)
        end
        w
    end
end

end

# test code
false && begin

using .uint384: UInt384, add, minus, modulo, multi

big(x::UInt384) = BigInt(x.h)*(BigInt(1) << 256) + BigInt(x.m)*(BigInt(1) << 128) + BigInt(x.l)
bytes = Array{UInt8}("0123456789abcdef")
string(x::BigInt) = String([bytes[i+1] for i in [(x >> (384 - j << 2)) & 0x0f for j in 1:96]])
string(x::UInt384) = String([[bytes[i+1] for i in [(x.h >> (128 - j << 2)) & 0x0f for j in 1:32]]; [bytes[i+1] for i in [(x.m >> (128 - j << 2)) & 0x0f for j in 1:32]]; [bytes[i+1] for i in [(x.l >> (128 - j << 2)) & 0x0f for j in 1:32]]])

for i in 1:100
    x = UInt384(0, rand(UInt32), rand(UInt128))
    y = UInt384(0, rand(UInt32), rand(UInt128))
    w = UInt384(0, 0, 0)

    multi(x, y, w)
    z = big(x) * big(y)
    # big(w) == z
    if big(w) != z
        @show x, y
        break
        # println(string(w)[1:32], "-", string(w)[33:48], "-", string(w)[49:64], "-", string(w)[65:96])
        # println(string(z)[1:32], "-", string(z)[33:48], "-", string(z)[49:64], "-", string(z)[65:96])
        # println()
    end

    # minus(x,y,z)
    # println(big(z) == (big(x) - big(y)))
end

end
