
using Shadowsocks

@static if VERSION < v"0.7.0-DEV.2005"
    using Base.Test
else
    using Test
end

# write your own tests here
@test 1 == 1

false && begin
# Poly1305
msg = b"Cryptographic Forum Research Group"
msg2 = [ones(UInt8, 16); b"Cryptographic Forum Research Group"]
key = [0x85; 0xd6; 0xbe; 0x78; 0x57; 0x55; 0x6d; 0x33; 
    0x7f; 0x44; 0x52; 0xfe; 0x42; 0xd5; 0x06; 0xa8; 
    0x01; 0x03; 0x80; 0x8a; 0xfb; 0x0d; 0xb2; 0xfd; 
    0x4a; 0xbf; 0xf6; 0xaf; 0x41; 0x49; 0xf5; 0x1b]
@test Poly1305.Poly1305MAC(msg, key) == [0xa8; 0x06; 0x1d; 0xc1; 0x30; 0x51; 0x36; 0xc6; 0xc2; 0x2b; 0x8b; 0xaf; 0x0c; 0x01; 0x27; 0xa9]
@test Poly1305.Poly1305MAC([msg, ], key) == [0xa8; 0x06; 0x1d; 0xc1; 0x30; 0x51; 0x36; 0xc6; 0xc2; 0x2b; 0x8b; 0xaf; 0x0c; 0x01; 0x27; 0xa9]

@test Poly1305.Poly1305MAC(msg2, key) == Poly1305.Poly1305MAC([ones(UInt8, 16), msg], key)
@test Poly1305.Poly1305MAC([ones(UInt8, 1); zeros(UInt8, 15); ones(UInt8, 16)], key) == Poly1305.Poly1305MAC([ones(UInt8, 1), ones(UInt8, 16)], key)

end # end of test Poly1305


text = b"julia00001111222233334444"
c = zeros(UInt8, 1024)
clen = Ref{UInt64}(0)
m = text
mlen = UInt64(length(m))
ad = b"imgk0000"
adlen = UInt64(length(ad))
nsec = C_NULL

key = rand(UInt8, 32)
nonce = rand(UInt8, 12)
Shadowsocks.crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, nsec, nonce, key)
r1 = c[1:clen[]]
Shadowsocks.crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, nsec, nonce, key, 1)
r2 = c[1:clen[]]

@test r1 == r2

ciphertext = r1
c = ciphertext
clen = UInt64(length(c))
m = zeros(UInt8, 1024)
mlen = Ref{UInt64}(0)
ad = b"imgk0000"
adlen = UInt64(length(ad))
nsec = C_NULL

Shadowsocks.crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, nsec, c, clen, ad, adlen, nonce, key)
r1 = m[1:mlen[]]
Shadowsocks.crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, nsec, c, clen, ad, adlen, nonce, key, 1)
r2 = m[1:mlen[]]

@test r1 == r2

ssConn = Shadowsocks.SSConnection(
	connect("www.baidu.com", 80),
	Shadowsocks.Cipher(Shadowsocks.SSServer()),
	rand(UInt8, 12),
	rand(UInt8, 12),
	rand(UInt8, 18),
	rand(UInt8, 32),
	rand(UInt8, 32)
)

buff = zeros(UInt8, 1024);
buff2 = zeros(UInt8, 1024);

Shadowsocks.encrypt(buff, b"julia", 5, ssConn)
Shadowsocks.encrypt(buff2, b"julia", 5, ssConn, 1)
