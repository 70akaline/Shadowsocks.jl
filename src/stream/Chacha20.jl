
module Chacha20

using ..Common: @lrot, @arraylittle, @arraylittle!

const ChachaKeyLen = 32
const ChachaNonceLen = 12
const OChachaNonceLen = 8
const XChachaNonceLen = 24
const ChachaState = Vector{UInt32}

function newChachaState(key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8})
    state = ChachaState(undef, 16)

    state[1:4] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    state[5:12] = @arraylittle(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(key)), 8))
    state[13] = counter
    state[14:16] = @arraylittle(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce)), 3))

    return state
end

function newHChachaState(key::Vector{UInt8}, nonce::Vector{UInt8})
    state = ChachaState(undef, 16)

    state[1:4] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    state[5:12] = @arraylittle(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(key)), 8))
    state[13:16] = @arraylittle(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce)), 4))

    return state
end

function newXChachaState(key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8})
    state = HChacha20Block(newHChachaState(key, nonce))

    state[5:12] = state[[1:4; 13:16]]
    state[1:4] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    state[13:14] = UInt32[counter & 0xffffffff; counter >> 32]
    state[15:16] = @arraylittle(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce) + 16), 2))

    return state
end

function newOChachaState(key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8})
    state = ChachaState(undef, 16)

    state[1:4] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    state[5:12] = @arraylittle(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(key)), 8))
    state[13:14] = UInt32[counter & 0xffffffff; counter >> 32]
    state[15:16] = @arraylittle(unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce)), 2))

    return state
end

@inline function UpdateChachaState(state::ChachaState, counter::UInt32)
    state[13] = counter
    return state
end

@inline function UpdateOChachaState(state::ChachaState, counter::UInt64)
    state[13:14] = UInt32[counter & 0xffffffff; counter >> 32]
    return state
end

macro QuaterRound(s, x, y, z, w)
    quote
        $(esc(s))[$(esc(x))] += $(esc(s))[$(esc(y))]; $(esc(s))[$(esc(w))] ⊻= $(esc(s))[$(esc(x))]; $(esc(s))[$(esc(w))] = @lrot($(esc(s))[$(esc(w))], 16)
        $(esc(s))[$(esc(z))] += $(esc(s))[$(esc(w))]; $(esc(s))[$(esc(y))] ⊻= $(esc(s))[$(esc(z))]; $(esc(s))[$(esc(y))] = @lrot($(esc(s))[$(esc(y))], 12)
        $(esc(s))[$(esc(x))] += $(esc(s))[$(esc(y))]; $(esc(s))[$(esc(w))] ⊻= $(esc(s))[$(esc(x))]; $(esc(s))[$(esc(w))] = @lrot($(esc(s))[$(esc(w))], 8 )
        $(esc(s))[$(esc(z))] += $(esc(s))[$(esc(w))]; $(esc(s))[$(esc(y))] ⊻= $(esc(s))[$(esc(z))]; $(esc(s))[$(esc(y))] = @lrot($(esc(s))[$(esc(y))], 7 )
    end
end

function Chacha20Block(state::ChachaState)::Array{UInt8}
    s = deepcopy(state)

    for i in 1:10
        @QuaterRound(s, 1, 5, 9 , 13)
        @QuaterRound(s, 2, 6, 10, 14)
        @QuaterRound(s, 3, 7, 11, 15)
        @QuaterRound(s, 4, 8, 12, 16)

        @QuaterRound(s, 1, 6, 11, 16)
        @QuaterRound(s, 2, 7, 12, 13)
        @QuaterRound(s, 3, 8, 9 , 14)
        @QuaterRound(s, 4, 5, 10, 15)
    end

    s += state
    @arraylittle!(s)

    return reinterpret(UInt8, s)
end

function HChacha20Block(s::ChachaState)
    for i in 1:10
        @QuaterRound(s, 1, 5, 9 , 13)
        @QuaterRound(s, 2, 6, 10, 14)
        @QuaterRound(s, 3, 7, 11, 15)
        @QuaterRound(s, 4, 8, 12, 16)

        @QuaterRound(s, 1, 6, 11, 16)
        @QuaterRound(s, 2, 7, 12, 13)
        @QuaterRound(s, 3, 8, 9 , 14)
        @QuaterRound(s, 4, 5, 10, 15)
    end

    return s
end

@inline function XChacha20Block(state::ChachaState)
    return Chacha20Block(state)
end

@inline function OChacha20Block(state::ChachaState)
    return Chacha20Block(state)
end

#  Chacha20_IETF
function Chacha20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt32(fld(len, 64))
    state = newChachaState(key, counter, nonce)

    ptrFrom = pointer(from)

    nblock > 0x00000000 && for i in 0x00000000:nblock-0x00000001
        keystream = Chacha20Block(UpdateChachaState(state, counter+i))
        @inbounds to[i * 64 + 1 : i * 64 + 64] = keystream .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + i * 64, 64)
    end

    left = len % 64
    if left != 0
        keystream = Chacha20Block(UpdateChachaState(state, counter+nblock))
        @inbounds to[nblock * 64 + 1 : nblock * 64 + left] = unsafe_wrap(Array{UInt8}, pointer(keystream), left) .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + nblock * 64, left)
    end

    return len
end

Chacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8}, text::Vector{UInt8}) = Chacha20Calculate(ciphertext, key, counter, nonce, text)
Chacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = Chacha20Encrypt(ciphertext, key, 0x00000000, nonce, text)

Chacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt32, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Chacha20Calculate(text, key, counter, nonce, ciphertext)
Chacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Chacha20Decrypt(text, key, 0x00000000, nonce, ciphertext)

# XChacha20
function XChacha20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt32(fld(len, 64))
    state = newXChachaState(key, counter, nonce)

    ptrFrom = pointer(from)

    nblock > 0x0000000000000000 && for i in 0x0000000000000000:nblock-0x0000000000000001
        keystream = XChacha20Block(UpdateOChachaState(state, counter+i))
        @inbounds to[i * 64 + 1 : i * 64 + 64] = keystream .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + i * 64, 64)
    end

    left = len % 64
    if left != 0
        keystream = XChacha20Block(UpdateOChachaState(state, counter+nblock))
        @inbounds to[nblock * 64 + 1 : nblock * 64 + left] = unsafe_wrap(Array{UInt8}, pointer(keystream), left) .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + nblock * 64, left)
    end

    return len
end

XChacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, text::Vector{UInt8}) = XChacha20Calculate(ciphertext, key, counter, nonce, text)
XChacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = XChacha20Encrypt(ciphertext, key, 0x0000000000000000, nonce, text)

XChacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = XChacha20Calculate(text, key, counter, nonce, ciphertext)
XChacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = XChacha20Decrypt(text, key, 0x0000000000000000, nonce, ciphertext)

# Original Chacha20
function OChacha20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt32(fld(len, 64))
    state = newOChachaState(key, counter, nonce)

    ptrFrom = pointer(from)

    nblock > 0x0000000000000000 && for i in 0x0000000000000000:nblock-0x0000000000000001
        keystream = OChacha20Block(UpdateOChachaState(state, counter+i))
        @inbounds to[i * 64 + 1 : i * 64 + 64] = keystream .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + i * 64, 64)
    end

    left = len % 64
    if left != 0
        keystream = OChacha20Block(UpdateOChachaState(state, counter+nblock))
        @inbounds to[nblock * 64 + 1 : nblock * 64 + left] = unsafe_wrap(Array{UInt8}, pointer(keystream), left) .⊻ unsafe_wrap(Array{UInt8}, ptrFrom + nblock * 64, left)
    end

    return len
end

OChacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, text::Vector{UInt8}) = OChacha20Calculate(ciphertext, key, counter, nonce, text)
OChacha20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = OChacha20Encrypt(ciphertext, key, 0x0000000000000000, nonce, text)

OChacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = OChacha20Calculate(text, key, counter, nonce, ciphertext)
OChacha20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = OChacha20Decrypt(text, key, 0x0000000000000000, nonce, ciphertext)

end # module
