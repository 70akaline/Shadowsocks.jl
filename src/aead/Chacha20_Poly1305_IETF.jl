
module Chacha20_Poly1305_IETF

using ..Chacha20
using ..Poly1305
using ..Common: @lebytes

function Poly1305KeyGen(key::Vector{UInt8}, nonce::Vector{UInt8})
    return unsafe_wrap(Array{UInt8}, pointer(Chacha20.Chacha20Block(Chacha20.newChachaState(key, 0x00000000, nonce))), 32)
end

function Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}, add::Vector{UInt8})
    nbytes = UInt64(Chacha20.Chacha20Encrypt(ciphertext, key, 0x00000001, nonce, text))

    macData = if add == UInt8[] 
        [unsafe_wrap(Array{UInt8}, pointer(ciphertext), nbytes), [@lebytes(UInt64(length(add)), 8); @lebytes(nbytes, 8)]]
    else
        [add, unsafe_wrap(Array{UInt8}, pointer(ciphertext), nbytes), [@lebytes(UInt64(length(add)), 8); @lebytes(nbytes, 8)]]
    end
    ciphertext[nbytes+1:nbytes+16] = Poly1305.Poly1305MAC(macData, Poly1305KeyGen(key, nonce))

    return nbytes+16, nothing
end

function Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}, add::Vector{UInt8})
    len = UInt64(length(ciphertext)-16)

    macData = if add == UInt8[]
        [unsafe_wrap(Array{UInt8}, pointer(ciphertext), len), [@lebytes(UInt64(length(add)), 8); @lebytes(len, 8)]]
    else 
        [add, unsafe_wrap(Array{UInt8}, pointer(ciphertext), len), [@lebytes(UInt64(length(add)), 8); @lebytes(len, 8)]]
    end 

    if Poly1305.Poly1305MAC(macData, Poly1305KeyGen(key, nonce)) != unsafe_wrap(Array{UInt8}, pointer(ciphertext)+len, 16)
        return nothing, "Authenticated Error"
    end

    nbytes = Chacha20.Chacha20Decrypt(text, key, 0x00000001, nonce, unsafe_wrap(Array{UInt8}, pointer(ciphertext), len))

    return nbytes, nothing
end

end # module
