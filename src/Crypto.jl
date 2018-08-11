
module Crypto

# Chacha20_Poly1305_IETF
include(joinpath(@__DIR__, "aead", "Chacha20_Poly1305_IETF.jl"))

# Chacha20_Poly1305
include(joinpath(@__DIR__, "aead", "Chacha20_Poly1305.jl"))

# XChacha20_Poly1305
include(joinpath(@__DIR__, "aead", "XChacha20_Poly1305_IETF.jl"))

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

end
