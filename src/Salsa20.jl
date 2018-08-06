
module Salsa20

const SalsaKeylen = 32
const SalsaNonceLen = 8
const XSalsaNonceLen = 24
const SalsaState = Vector{UInt32}

function lrot(x::UInt32, n::Integer)
    return x << n | x >> (32-n)
end

macro lrot(x, n)
    quote
        $(esc(x)) << $(esc(n)) | $(esc(x)) >> (32-$(esc(n)))
    end
end

function newSalsaState(key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8})
    s = SalsaState(16)
    s[[1; 6; 11; 16]] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    s[[2:5; 12:15]] = map(ltoh, unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(key)), 8))
    s[9:10] = UInt32[counter & 0xffff; counter >> 32]
    s[7:8] = map(ltoh, unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce)), 2))

    return s
end

function newHSalsaState(key::Vector{UInt8}, nonce::Vector{UInt8})
    s = SalsaState(16)
    s[[1; 6; 11; 16]] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    s[[2:5; 12:15]] = map(ltoh, unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(key)), 8))
    s[7:10] = map(ltoh, unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce)), 4))

    return s
end

function newXSalsaState(key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8})
    s = newHSalsaState(key, unsafe_wrap(Array{UInt8}, pointer(nonce), 16))
    s[[2:5; 12:15]] = HSlasa10Block(s)[[1; 6; 11; 16; 7; 8; 9; 10]]
    s[[1; 6; 11; 16]] = [0x61707865; 0x3320646e; 0x79622d32; 0x6b206574]
    s[9:10] = UInt32[counter & 0xffff; counter >> 32]
    s[7:8] = map(ltoh, unsafe_wrap(Array{UInt32}, Ptr{UInt32}(pointer(nonce) + 16), 2))

    return s
end

function UpdateSalsaState(state::SalsaState, counter::UInt64)
    state[9:10] = UInt32[counter & 0xffff; counter >> 32]

    return state
end

function QuaterRound(a::UInt32, b::UInt32, c::UInt32, d::UInt32)
    b ⊻= lrot((a + d), 7 )
    c ⊻= lrot((b + a), 9 )
    d ⊻= lrot((c + b), 13)
    a ⊻= lrot((d + c), 18)
    
    return a, b, c, d
end

function Salsa20Block(state::SalsaState)
    s = deepcopy(state)

    for i in 1:10
        s[1 ], s[5 ], s[9 ], s[13] = QuaterRound(s[1 ], s[5 ], s[9 ], s[13])
        s[6 ], s[10], s[14], s[2 ] = QuaterRound(s[6 ], s[10], s[14], s[2 ])
        s[11], s[15], s[3 ], s[7 ] = QuaterRound(s[11], s[15], s[3 ], s[7 ])
        s[16], s[4 ], s[8 ], s[12] = QuaterRound(s[16], s[4 ], s[8 ], s[12])

        s[1 ], s[2 ], s[3 ], s[4 ] = QuaterRound(s[1 ], s[2 ], s[3 ], s[4 ])
        s[6 ], s[7 ], s[8 ], s[5 ] = QuaterRound(s[6 ], s[7 ], s[8 ], s[5 ])
        s[11], s[12], s[9 ], s[10] = QuaterRound(s[11], s[12], s[9 ], s[10])
        s[16], s[13], s[14], s[15] = QuaterRound(s[16], s[13], s[14], s[15])
    end

    s += state

    map!(htol, s, s)

    return reinterpret(UInt8, s)
end

function HSalsa10Block(state::SalsaState)
    for i in 1:5
        state[1 ], state[5 ], state[9 ], state[13] = QuaterRound(state[1 ], state[5 ], state[9 ], state[13])
        state[6 ], state[10], state[14], state[2 ] = QuaterRound(state[6 ], state[10], state[14], state[2 ])
        state[11], state[15], state[3 ], state[7 ] = QuaterRound(state[11], state[15], state[3 ], state[7 ])
        state[16], state[4 ], state[8 ], state[12] = QuaterRound(state[16], state[4 ], state[8 ], state[12])

        state[1 ], state[2 ], state[3 ], state[4 ] = QuaterRound(state[1 ], state[2 ], state[3 ], state[4 ])
        state[6 ], state[7 ], state[8 ], state[5 ] = QuaterRound(state[6 ], state[7 ], state[8 ], state[5 ])
        state[11], state[12], state[9 ], state[10] = QuaterRound(state[11], state[12], state[9 ], state[10])
        state[16], state[13], state[14], state[15] = QuaterRound(state[16], state[13], state[14], state[15])
    end
    
    return state
end

function XSalsa10Block(state::SalsaState)
    s = deepcopy(state)

    for i in 1:5
        s[1 ], s[5 ], s[9 ], s[13] = QuaterRound(s[1 ], s[5 ], s[9 ], s[13])
        s[6 ], s[10], s[14], s[2 ] = QuaterRound(s[6 ], s[10], s[14], s[2 ])
        s[11], s[15], s[3 ], s[7 ] = QuaterRound(s[11], s[15], s[3 ], s[7 ])
        s[16], s[4 ], s[8 ], s[12] = QuaterRound(s[16], s[4 ], s[8 ], s[12])

        s[1 ], s[2 ], s[3 ], s[4 ] = QuaterRound(s[1 ], s[2 ], s[3 ], s[4 ])
        s[6 ], s[7 ], s[8 ], s[5 ] = QuaterRound(s[6 ], s[7 ], s[8 ], s[5 ])
        s[11], s[12], s[9 ], s[10] = QuaterRound(s[11], s[12], s[9 ], s[10])
        s[16], s[13], s[14], s[15] = QuaterRound(s[16], s[13], s[14], s[15])
    end

    s += state

    map!(htol, s, s)

    return reinterpret(UInt8, s)
end

function Salsa20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt64(floor(len/64))
    state = newSalsaState(key, counter, nonce)

    nblock > 0x0000000000000000 && for i in 0x0000000000000000:nblock-0x0000000000000001
        keystream = Salsa20Block(UpdateSalsaState(state, counter+i))

        for j in 0x0000000000000001:0x0000000000000040
            to[i << 6 + j] = keystream[j] ⊻ from[i << 6 + j]
        end
    end

    left = len % 64
    if left != 0
        keystream = Salsa20Block(UpdateSalsaState(state, counter+nblock))

        for j in 1:left
            to[nblock << 6 + j] = keystream[j] ⊻ from[nblock << 6 + j]
        end
    end

    return len
end

Salsa20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, text::Vector{UInt8}) = Salsa20Calculate(ciphertext, key, counter, nonce, text)
Salsa0Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = Salsa20Encrypt(ciphertext, key, 0x0000000000000001, nonce, text)

Salsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Salsa20Calculate(text, key, counter, nonce, ciphertext)
Salsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = Salsa20Decrypt(text, key, 0x0000000000000001, nonce, ciphertext)

function XSalsa20Calculate(to::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, from::Vector{UInt8})
    len = sizeof(from)
    nblock = UInt64(floor(len/64))
    state = newXSalsaState(key, counter, nonce)

    nblock > 0x0000000000000000 && for i in 0x0000000000000000:nblock-0x0000000000000001
        keystream = XSalsa10Block(UpdateSalsaState(state, counter+i))

        for j in 0x0000000000000001:0x0000000000000040
            to[i << 6 + j] = keystream[j] ⊻ from[i << 6 + j]
        end
    end

    left = len % 64
    if left != 0
        keystream = XSalsa10Block(UpdateSalsaState(state, counter+nblock))

        for j in 1:left
            to[nblock << 6 + j] = keystream[j] ⊻ from[nblock << 6 + j]
        end
    end

    return len
end

XSalsa20Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, text::Vector{UInt8}) = XSalsa20Calculate(ciphertext, key, counter, nonce, text)
XSalsa0Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}) = XSalsa20Encrypt(ciphertext, key, 0x0000000000000001, nonce, text)

XSalsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, counter::UInt64, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = XSalsa20Calculate(text, key, counter, nonce, ciphertext)
XSalsa20Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}) = XSalsa20Decrypt(text, key, 0x0000000000000001, nonce, ciphertext)

end # module
