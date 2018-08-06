
module Crypto

# Chacha20_IETF_Poly1305
include("Chacha20_IETF_Poly1305.jl")
Chacha20_IETF_Poly1305_Decrypt = Chacha20_IETF_Poly1305.Decrypt
Chacha20_IETF_Poly1305_Encrypt = Chacha20_IETF_Poly1305.Encrypt

# Salsa20
include("Salsa20.jl")

# Chacha20_IETF
include("Chacha20.jl")

end
