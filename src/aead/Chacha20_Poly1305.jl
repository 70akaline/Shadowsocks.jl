
module Chacha20_Poly1305 # not passed test yet

using ..Chacha20
using ..Poly1305
using ..Common: @LittleEndianBytes

function Poly1305KeyGen(key::Vector{UInt8}, nonce::Vector{UInt8})
    return unsafe_wrap(Array{UInt8}, pointer(Chacha20.OChacha20Block(Chacha20.newOChachaState(key, 0x0000000000000000, nonce))), 32)
end

function Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}, add::Vector{UInt8})
    nbytes = UInt64(Chacha20.OChacha20Encrypt(ciphertext, key, 0x0000000000000001, nonce, text))

    macData = if add == UInt8[] 
        [unsafe_wrap(Array{UInt8}, pointer(ciphertext), nbytes), [@LittleEndianBytes(UInt64(length(add))); @LittleEndianBytes(nbytes)]]
    else
        [add, unsafe_wrap(Array{UInt8}, pointer(ciphertext), nbytes), [@LittleEndianBytes(UInt64(length(add))); @LittleEndianBytes(nbytes)]]
    end
    ciphertext[nbytes+1:nbytes+16] = Poly1305.Poly1305MAC(macData, Poly1305KeyGen(key, nonce))

    return nbytes+16, nothing
end

function Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}, add::Vector{UInt8})
    len = UInt64(length(ciphertext)-16)

    macData = if add == UInt8[]
        [unsafe_wrap(Array{UInt8}, pointer(ciphertext), len), [@LittleEndianBytes(UInt64(length(add))); @LittleEndianBytes(len)]]
    else 
        [add, unsafe_wrap(Array{UInt8}, pointer(ciphertext), len), [@LittleEndianBytes(UInt64(length(add))); @LittleEndianBytes(len)]]
    end 

    if Poly1305.Poly1305MAC(macData, Poly1305KeyGen(key, nonce)) != unsafe_wrap(Array{UInt8}, pointer(ciphertext)+len, 16)
        return nothing, "Authenticated Error"
    end

    nbytes = Chacha20.OChacha20Decrypt(text, key, 0x0000000000000001, nonce, unsafe_wrap(Array{UInt8}, pointer(ciphertext), len))

    return nbytes, nothing
end

end # module
