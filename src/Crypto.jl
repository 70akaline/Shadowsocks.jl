
module Crypto

include("Chacha20.jl")
include("Poly1305.jl")

function LeBytes(num::UInt64, n::Integer)
    return reinterpret(UInt8, [htol(num); ])[1:n]
end

# =========Chacha20-Poly1305-ietf================

function Poly1305KeyGen(key::Vector{UInt8}, nonce::Vector{UInt8})
    return Chacha20.Chacha20Block(Chacha20.newChachaState(key, 0x00000000, nonce))[1:32]
end

function Chacha20_IETF_Poly1305_Encrypt(ciphertext::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, text::Vector{UInt8}, add::Vector{UInt8})

    nbytes = Chacha20.Chacha20Encrypt(ciphertext, key, nonce, text)
	macData = if add == UInt8[] 
        [unsafe_wrap(Array{UInt8}, pointer(ciphertext), nbytes), [LeBytes(UInt64(length(add)), 8); LeBytes(UInt64(nbytes), 8)]]
	else
		[add, unsafe_wrap(Array{UInt8}, pointer(ciphertext), nbytes), [LeBytes(UInt64(length(add)), 8); LeBytes(UInt64(nbytes), 8)]]
	end
    ciphertext[nbytes+1:nbytes+16] = Poly1305.Poly1305MAC(macData, Poly1305KeyGen(key, nonce))

    return nbytes+16
end

function Chacha20_IETF_Poly1305_Decrypt(text::Vector{UInt8}, key::Vector{UInt8}, nonce::Vector{UInt8}, ciphertext::Vector{UInt8}, add::Vector{UInt8})

    len = length(ciphertext)-16
	macData = if add == UInt8[]
        [unsafe_wrap(Array{UInt8}, pointer(ciphertext), len), [LeBytes(UInt64(length(add)), 8); LeBytes(UInt64(len), 8)]]
    else 
        [add, unsafe_wrap(Array{UInt8}, pointer(ciphertext), len), [LeBytes(UInt64(length(add)), 8); LeBytes(UInt64(len), 8)]]
    end 
    if Poly1305.Poly1305MAC(macData, Poly1305KeyGen(key, nonce)) != ciphertext[end-15:end]
        return nothing
    end
    nbytes = Chacha20.Chacha20Decrypt(text, key, nonce, unsafe_wrap(Array{UInt8}, pointer(ciphertext), len))

    return nbytes
end

# ===============================================

end
