
module Chacha20

# ======Chacha20==========

const ChachaKeyLen = 32
const ChachaNonceLen = 12
const OChachaNonceLen = 8
const XChachaNonceLen = 24
const ChachaState = Vector{UInt32}

function lrot(x::UInt32, n::Integer)
    return x << n | x >> (32-n)
end

macro lrot(x, n)
    quote
        $(esc(x)) << $(esc(n)) | $(esc(x)) >> (32-$(esc(n)))
    end
end

function newChachaState(key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8})
    state = ChachaState(undef, 16)

    state[1:4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    ptr = Ptr{UInt32}(pointer(key))
    for i in 5:12
        state[i] = ltoh(unsafe_load(ptr, i-4))
    end

    state[13] = counter

    ptr = Ptr{UInt32}(pointer(nonce))
    for i in 14:16
        state[i] = ltoh(unsafe_load(ptr, i-13))
    end

    return state
end

function newHChachaState()
end

function newXChachaState()
end

function newOChachaState()
end

function UpdateChachaState(state::ChachaState, counter::UInt32)
    state[13] = counter
    return state
end

function QuaterRound(a::UInt32, b::UInt32, c::UInt32, d::UInt32)
    a += b; d ⊻= a; d = @lrot(d, 16)
    c += d; b ⊻= c; b = @lrot(b, 12)
    a += b; d ⊻= a; d = @lrot(d, 8)
    c += d; b ⊻= c; b = @lrot(b, 7)

    return a, b, c, d
end

macro QuaterRound(s, x, y, z, w)
    quote
        $(esc(s))[$(esc(x))] += $(esc(s))[$(esc(y))]; $(esc(s))[$(esc(w))] ⊻= $(esc(s))[$(esc(x))]; $(esc(s))[$(esc(w))] = @lrot($(esc(s))[$(esc(w))], 16)
        $(esc(s))[$(esc(z))] += $(esc(s))[$(esc(w))]; $(esc(s))[$(esc(y))] ⊻= $(esc(s))[$(esc(z))]; $(esc(s))[$(esc(y))] = @lrot($(esc(s))[$(esc(y))], 12)
        $(esc(s))[$(esc(x))] += $(esc(s))[$(esc(y))]; $(esc(s))[$(esc(w))] ⊻= $(esc(s))[$(esc(x))]; $(esc(s))[$(esc(w))] = @lrot($(esc(s))[$(esc(w))], 8 )
        $(esc(s))[$(esc(z))] += $(esc(s))[$(esc(w))]; $(esc(s))[$(esc(y))] ⊻= $(esc(s))[$(esc(z))]; $(esc(s))[$(esc(y))] = @lrot($(esc(s))[$(esc(y))], 7 )
    end
end

function Chacha20Block(state::ChachaState, test)
    s = deepcopy(state)

    for i in 1:10
        s[1], s[5], s[9 ], s[13] = QuaterRound(s[1], s[5], s[9 ], s[13])
        s[2], s[6], s[10], s[14] = QuaterRound(s[2], s[6], s[10], s[14])
        s[3], s[7], s[11], s[15] = QuaterRound(s[3], s[7], s[11], s[15])
        s[4], s[8], s[12], s[16] = QuaterRound(s[4], s[8], s[12], s[16])

        s[1], s[6], s[11], s[16] = QuaterRound(s[1], s[6], s[11], s[16])
        s[2], s[7], s[12], s[13] = QuaterRound(s[2], s[7], s[12], s[13])
        s[3], s[8], s[9 ], s[14] = QuaterRound(s[3], s[8], s[9 ], s[14])
        s[4], s[5], s[10], s[15] = QuaterRound(s[4], s[5], s[10], s[15])
    end

    s += state

    map!(htol, s, s)

    return reinterpret(UInt8, s)
end

function Chacha20Block(state::ChachaState)
    s = deepcopy(state)

    for i in 1:10
        @QuaterRound(s, 1, 5, 9, 13)
        @QuaterRound(s, 2, 6, 10, 14)
        @QuaterRound(s, 3, 7, 11, 15)
        @QuaterRound(s, 4, 8, 12, 16)

        @QuaterRound(s, 1, 6, 11, 16)
        @QuaterRound(s, 2, 7, 12, 13)
        @QuaterRound(s, 3, 8, 9, 14)
        @QuaterRound(s, 4, 5, 10, 15)
    end

    s += state

    map!(htol, s, s)

    return reinterpret(UInt8, s)
end

function HChacha10Block()
end

function XChacha10Block()
end

function Chacha20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt32(floor(len/64))
    state = newChachaState(key, counter, nonce)

    nblock > 0x00000000 && for i in 0x00000000:nblock-0x00000001
        keystream = Chacha20Block(UpdateChachaState(state, counter+i))

        for j in 0x00000001:0x00000040
            to[i << 6 + j] = keystream[j] ⊻ from[i << 6 + j]
        end
    end

    left = len % 64
    if left != 0
        keystream = Chacha20Block(UpdateChachaState(state, counter+nblock))

        for j in 1:left
            to[nblock << 6 + j] = keystream[j] ⊻ from[nblock << 6 + j]
        end
    end

    return len
end

Chacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8}, text::Vector{UInt8}) = Chacha20Calculate(ciphertext, key, counter, nonce, text)
Chacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = Chacha20Encrypt(ciphertext, key, 0x00000001, nonce, text)

Chacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Chacha20Calculate(text, key, counter, nonce, ciphertext)
Chacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Chacha20Decrypt(text, key, 0x00000001, nonce, ciphertext)

function XChacha20Calculate()
end

end # end module
