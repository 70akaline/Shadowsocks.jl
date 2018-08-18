
module Crypto

module Common

macro lrot(x, n)
    quote
        $(esc(x)) << $(esc(n)) | $(esc(x)) >> (32-$(esc(n)))
    end
end

@inline function LeBytes(num::UInt64, n::Integer)
    return unsafe_wrap(Array{UInt8}, Ptr{UInt8}(pointer([htol(num); ])), n)
end

@static if Base.ENDIAN_BOM == 0x04030201
	global little(x) = x
	global little!(x) = x
	global big(x) = begin map(hton, x); x end
	global big!(x) = begin map!(hton, x, x); x end
elseif Base.ENDIAN_BOM == 0x01020304
	global little(x) = begin map(htol, x); x end
	global little!(x) = begin map!(htol, x, x); x end
	global big(x) = x
	global big!(x) = x
end

end # module

# Salsa20
include(joinpath(@__DIR__, "stream", "Salsa20.jl"))

# Chacha20_IETF
include(joinpath(@__DIR__, "stream", "Chacha20.jl"))

# Poly1305
include(joinpath(@__DIR__, "mac", "Poly1305.jl"))

# MD5
include(joinpath(@__DIR__, "hash", "MD5.jl"))

# HKDF
include(joinpath(@__DIR__, "kdf", "HKDF.jl"))

# Chacha20_Poly1305_IETF
include(joinpath(@__DIR__, "aead", "Chacha20_Poly1305_IETF.jl"))

# Chacha20_Poly1305
include(joinpath(@__DIR__, "aead", "Chacha20_Poly1305.jl"))

# XChacha20_Poly1305
include(joinpath(@__DIR__, "aead", "XChacha20_Poly1305_IETF.jl"))

end
