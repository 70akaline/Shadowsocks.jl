
module Crypto

module Common

macro lrot(x, n)
    quote
        $(esc(x)) << $(esc(n)) | $(esc(x)) >> (32-$(esc(n)))
    end
end

macro lebytes(x, n)
    quote
        UInt8[$(esc(x)) >> (i * 8) & 0xff for i in 0:$(esc(n))-1]
    end
end

macro little!(x)
    if Base.ENDIAN_BOM == 0x04030201
        quote
            $(esc(x))
        end
    elseif Base.ENDIAN_BOM == 0x01020304
        quote
            bswap($(esc(x)))
        end
    end
end

macro little(x)
    if Base.ENDIAN_BOM == 0x04030201
        quote
            $(esc(x))
        end
    elseif Base.ENDIAN_BOM == 0x01020304
        quote
            htol($(esc(x)))
        end
    end
end

macro arraylittle!(x)
    if Base.ENDIAN_BOM == 0x04030201
        quote
            $(esc(x))
        end
    elseif Base.ENDIAN_BOM == 0x01020304
        quote
            map!(bswap, $(esc(x)), $(esc(x)))
        end
    end
end

macro arraylittle(x)
    if Base.ENDIAN_BOM == 0x04030201
        quote
            $(esc(x))
        end
    elseif Base.ENDIAN_BOM == 0x01020304
        quote
            map(bswap, $(esc(x)))
        end
    end
end

end # module

# Salsa20
include("stream/Salsa20.jl")

# Chacha20
include("stream/Chacha20.jl")

# Poly1305
include("mac/Poly1305.jl")

# MD5
include("hash/MD5.jl")

# HKDF
include("kdf/HKDF.jl")

# Chacha20_Poly1305_IETF
include("aead/Chacha20_Poly1305_IETF.jl")

# Chacha20_Poly1305
include("aead/Chacha20_Poly1305.jl")

# XChacha20_Poly1305_IETF
include("aead/XChacha20_Poly1305_IETF.jl")

end
