
module Salsa20

using ..Common

const SalsaKeylen = 32
const SalsaNonceLen = 8
const XSalsaNonceLen = 24
const SalsaState = Vector{UInt32}

function newSalsaState(key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8})
    s = SalsaState(undef, 16)

    s[[1; 6; 11; 16]] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    s[[2:5; 12:15]] = Common.little(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(key)), 8))
    s[9:10] = UInt32[counter & 0xffff; counter >> 32]
    s[7:8] = Common.little(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce)), 2))

    return s
end

function newHSalsaState(key::Vector{UInt8}, nonce::Vector{UInt8})
    s = SalsaState(undef, 16)

    s[[1; 6; 11; 16]] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    s[[2:5; 12:15]] = Common.little(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(key)), 8))
    s[7:10] = Common.little(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce)), 4))

    return s
end

function newXSalsaState(key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8})
    s = HSalsa20Block(newHSalsaState(key, nonce))

    s[[2:5; 12:15]] = s[[1; 6; 11; 16; 7; 8; 9; 10]]
    s[[1; 6; 11; 16]] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    s[9:10] = UInt32[counter & 0xffff; counter >> 32]
    s[7:8] = Common.little(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce) + 16), 2))

    return s
end

@inline function UpdateSalsaState(state::SalsaState, counter::UInt64)
    state[9:10] = UInt32[counter & 0xffff; counter >> 32]
    return state
end

macro QuaterRound(s, x, y, z, w)
    quote
        t = $(esc(s))[$(esc(x))] + $(esc(s))[$(esc(w))]; $(esc(s))[$(esc(y))] ⊻= Common.@lrot(t, 7 )
        t = $(esc(s))[$(esc(y))] + $(esc(s))[$(esc(x))]; $(esc(s))[$(esc(z))] ⊻= Common.@lrot(t, 9 )
        t = $(esc(s))[$(esc(z))] + $(esc(s))[$(esc(y))]; $(esc(s))[$(esc(w))] ⊻= Common.@lrot(t, 13)
        t = $(esc(s))[$(esc(w))] + $(esc(s))[$(esc(z))]; $(esc(s))[$(esc(x))] ⊻= Common.@lrot(t, 18)
    end
end

function Salsa20Block(state::SalsaState)
    s = deepcopy(state)

    for i in 1:10
        @QuaterRound(s, 1 , 5 , 9 , 13)
        @QuaterRound(s, 6 , 10, 14, 2 )
        @QuaterRound(s, 11, 15, 3 , 7 )
        @QuaterRound(s, 16, 4 , 8 , 12)

        @QuaterRound(s, 1 , 2 , 3 , 4 )
        @QuaterRound(s, 6 , 7 , 8 , 5 )
        @QuaterRound(s, 11, 12, 9 , 10)
        @QuaterRound(s, 16, 13, 14, 15)
    end

    s += state
    s = Common.little!(s)

    return reinterpret(UInt8, s)
end

function HSalsa20Block(state::SalsaState)
    for i in 1:10
        @QuaterRound(state, 1 , 5 , 9 , 13)
        @QuaterRound(state, 6 , 10, 14, 2 )
        @QuaterRound(state, 11, 15, 3 , 7 )
        @QuaterRound(state, 16, 4 , 8 , 12)

        @QuaterRound(state, 1 , 2 , 3 , 4 )
        @QuaterRound(state, 6 , 7 , 8 , 5 )
        @QuaterRound(state, 11, 12, 9 , 10)
        @QuaterRound(state, 16, 13, 14, 15)
    end
    
    return state
end

@inline function XSalsa20Block(state::SalsaState)
    return Salsa20Block(state)
end

function Salsa20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt32(fld(len, 64))
    state = newSalsaState(key, counter, nonce)

    ptrFrom = pointer(from)

    nblock > 0x0000000000000000 && for i in 0x0000000000000000:nblock-0x0000000000000001
        keystream = Salsa20Block(UpdateSalsaState(state, counter+i))
        @inbounds to[i << 6 + 1 : i << 6 + 64] = keystream .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + i << 6, 64)
    end

    left = len % 64
    if left != 0
        keystream = Salsa20Block(UpdateSalsaState(state, counter+nblock))
        @inbounds to[nblock << 6 + 1 : nblock << 6 + left] = unsafe_wrap(Array{UInt8}, pointer(keystream), left) .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + nblock << 6, left)
    end

    return len
end

Salsa20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, text::Vector{UInt8}) = Salsa20Calculate(ciphertext, key, counter, nonce, text)
Salsa20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = Salsa20Encrypt(ciphertext, key, 0x0000000000000000, nonce, text)

Salsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Salsa20Calculate(text, key, counter, nonce, ciphertext)
Salsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Salsa20Decrypt(text, key, 0x0000000000000000, nonce, ciphertext)

function XSalsa20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt32(fld(len, 64))
    state = newXSalsaState(key, counter, nonce)

    ptrFrom = pointer(from)

    nblock > 0x0000000000000000 && for i in 0x0000000000000000:nblock-0x0000000000000001
        keystream = XSalsa20Block(UpdateSalsaState(state, counter+i))
        @inbounds to[i << 6 + 1 : i << 6 + 64] = keystream .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + i << 6, 64)
    end

    left = len % 64
    if left != 0
        keystream = XSalsa20Block(UpdateSalsaState(state, counter+nblock))
        @inbounds to[nblock << 6 + 1 : nblock << 6 + left] = unsafe_wrap(Array{UInt8}, pointer(keystream), left) .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + nblock << 6, left)
    end

    return len
end

XSalsa20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, text::Vector{UInt8}) = XSalsa20Calculate(ciphertext, key, counter, nonce, text)
XSalsa20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = XSalsa20Encrypt(ciphertext, key, 0x0000000000000000, nonce, text)

XSalsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = XSalsa20Calculate(text, key, counter, nonce, ciphertext)
XSalsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = XSalsa20Decrypt(text, key, 0x0000000000000000, nonce, ciphertext)

end # module
