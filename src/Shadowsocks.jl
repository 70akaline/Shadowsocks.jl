__precompile__(false)
# 
#
#  
# A Shadowsocks implementation written in Julia
# Create by John Xiong <imgk@mail.ustc.edu.cn>
# 
# 
# 
# 

module Shadowsocks

export SSServer, SSClient, run

import Base.run
import Base.read
import Base.write
import Base.isopen
import Base.close

const Bytes = Array{UInt8}
const MaxSize = 0x3FFF
const MD5Len = 16
const METHOD = Dict{String, Dict{String, Integer}}(
    "CHACHA20-POLY1305-IETF" => Dict{String, Integer}("KEYLEN" => Csize_t(32), "TAGLEN" => Csize_t(16), "IVLEN" => Csize_t(12)),
    "XCHACHA20-POLY1305-IETF" => Dict{String, Integer}("KEYLEN" => Csize_t(32), "TAGLEN" => Csize_t(16), "IVLEN" => Csize_t(24)),
    "AES-256-GCM" => Dict{String, Integer}("KEYLEN" => Csize_t(32), "TAGLEN" => Csize_t(16), "IVLEN" => Csize_t(12)))

macro log(message)
    quote
        println(STDOUT, Dates.now(), " : ", $message)
    end
end

macro dlsym(func, lib)
    z, zlocal = gensym(string(func)), gensym()
    eval(current_module(), :(global $z = C_NULL))
    z = esc(z)
    quote
        let $zlocal::Ptr{Void} = $z::Ptr{Void}
            if $zlocal == C_NULL
                $zlocal = Libdl.dlsym($(esc(lib))::Ptr{Void}, $(esc(func)))
                global $z = $zlocal
            end
            $zlocal
        end
    end
end

function (++)(iv::Bytes)
    for i in 1:length(iv)
        iv[i] += 0x01
        if iv[i] != 0x00
            break
        end
    end
end

mutable struct SSConfig
    host::IPAddr
    port::Integer
    lisPort::Union{Integer, Void}
    method::String
    password::String
end
SSServer(ip, port, method, password) = SSConfig(ip, port, nothing, method, password)
SSServer() = SSServer(getipaddr(), 8388, "CHACHA20-POLY1305-IETF", "imgk0000")
SSClient(ip, port, lisPort, method, password) = SSConfig(ip, port, lisPort, method, password)
SSClient() = SSConfig(getipaddr(), 8388, 1080, "CHACHA20-POLY1305-IETF", "imgk0000")

mutable struct Cipher
    method::Union{String, Void}
    key::Union{Bytes, Void}
    keylen::Csize_t
    ivlen::Csize_t
    taglen::Union{Integer, Void}
    encrypt::Union{Function, Void}
    decrypt::Union{Function, Void}
end
function Cipher(config::SSConfig) 
    cipher = Cipher(
        config.method,
        genkeys(METHOD[config.method]["KEYLEN"], config.password),
        METHOD[config.method]["KEYLEN"],
        METHOD[config.method]["IVLEN"],
        METHOD[config.method]["TAGLEN"],
        nothing,
        nothing)

    if config.method == "CHACHA20-POLY1305-IETF"
        cipher.encrypt = crypto_aead_chacha20poly1305_ietf_encrypt
        cipher.decrypt = crypto_aead_chacha20poly1305_ietf_decrypt
    elseif config.method == "XCHACHA20-POLY1305-IETF"
        cipher.encrypt = crypto_aead_xchacha20poly1305_ietf_encrypt
        cipher.decrypt = crypto_aead_xchacha20poly1305_ietf_decrypt
    elseif config.method == "AES-256-GCM"
        cipher.encrypt = crypto_aead_aes256gcm_encrypt
        cipher.decrypt = crypto_aead_aes256gcm_decrypt
    end

    return cipher
end

mutable struct SSConnection
    conn::Union{TCPSocket, Void}
    cipher::Union{Cipher, Void}
    ivDecrypt::Union{Bytes, Void}
    ivEncrypt::Union{Bytes, Void}
    tagCache::Union{Bytes, Void}
    keyDecrypt::Union{Bytes, Void}
    keyEncrypt::Union{Bytes, Void}
end

function close(ssConn::SSConnection)
    return close(ssConn.conn)
end

function isopen(ssConn::SSConnection)
    return isopen(ssConn.conn)
end

function init(ssConn::SSConnection, buff::Bytes, nbytes::Union{Integer, Void})
    saltlen = max(16, ssConn.cipher.keylen)

    nbytes == nothing && begin
        salt = Bytes(saltlen)
        nbytes, err = read(ssConn.conn, salt, saltlen)
        if err != nothing
            return err
        end

        ssConn.keyDecrypt, err = gensubkey(salt, ssConn.cipher.key, ssConn.cipher.keylen)
        if err != nothing
            return err
        end

        nbytes, err = read(ssConn, buff)
        if err != nothing
            return err
        end

        salt[:] = rand(UInt8, ssConn.cipher.keylen)
        ssConn.keyEncrypt, err = gensubkey(salt, ssConn.cipher.key, ssConn.cipher.keylen)
        if err != nothing
            return err
        end

        err = write(ssConn.conn, salt, saltlen)
        if err != nothing
            return err
        end

        return nothing
    end

    begin
        salt = rand(UInt8, saltlen)
        ssConn.keyEncrypt, err = gensubkey(salt, ssConn.cipher.key, ssConn.cipher.keylen)
        if err != nothing
            return err
        end

        err = write(ssConn.conn, salt, saltlen)
        if err != nothing
            return err
        end

        err = write(ssConn, buff, nbytes)
        if err != nothing
            return err
        end

        nbytes, err = read(ssConn.conn, salt, saltlen)
        if err != nothing
            return err
        end

        ssConn.keyDecrypt, err = gensubkey(salt, ssConn.cipher.key, ssConn.cipher.keylen)
        if err != nothing
            return err
        end

        return nothing
    end
end

# ==================
# ====SIP002========
# "ss://chacha20-poly1305-ietf:imgk0000@192.168.0.1:1080"
# "ss://chacha20-poly1305-ietf:imgk0000@:1080"
function parseURI(text::String)
    if text[1:5] != "ss://"
        return nothing, "Invalid Config"
    end

    r = match(r"ss://(?<method>[\w-]+):(?<password>\w+)@(?<ip>[0-9\.]*):(?<port>\d+)", text)

    if r["ip"] == ""
        return SSServer(getipaddr() isa IPv4 ? IPv4(0) : IPv6(0), parse(UInt16, r["port"]), uppercase(r["method"]), r["password"]), nothing
    else
        return SSClient(parse(IPAddr, r["ip"]), parse(UInt16, r["port"]), 1080, uppercase(r["method"]), r["password"]), nothing
    end
end

# ==================

# ==================
# ====libsodium=====

const libsodium = Libdl.dlopen(joinpath(@__DIR__, "libsodium"))
const c_sodium_init = @dlsym("sodium_init", libsodium)
const c_crypto_aead_chacha20poly1305_ietf_encrypt = @dlsym("crypto_aead_chacha20poly1305_ietf_encrypt", libsodium)
const c_crypto_aead_chacha20poly1305_ietf_decrypt = @dlsym("crypto_aead_chacha20poly1305_ietf_decrypt", libsodium)
const c_crypto_aead_xchacha20poly1305_ietf_encrypt = @dlsym("crypto_aead_xchacha20poly1305_ietf_encrypt", libsodium)
const c_crypto_aead_xchacha20poly1305_ietf_decrypt = @dlsym("crypto_aead_xchacha20poly1305_ietf_decrypt", libsodium)
const c_crypto_aead_aes256gcm_encrypt = @dlsym("crypto_aead_aes256gcm_encrypt", libsodium)
const c_crypto_aead_aes256gcm_decrypt = @dlsym("crypto_aead_aes256gcm_decrypt", libsodium)

function sodium_init()
    return ccall(c_sodium_init, Cint, (), )
end

function crypto_aead_chacha20poly1305_ietf_encrypt(
    c::Bytes, clen::Ref{UInt64}, m::Bytes, mlen::UInt64, ad::Bytes, adlen::UInt64, nsec::Ptr{Void}, npub::Bytes, k::Bytes)

    return ccall(c_crypto_aead_chacha20poly1305_ietf_encrypt, 
        Cint, 
        (Ref{Cuchar}, Ref{Csize_t}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ptr{Void}, Ref{Cuchar}, Ref{Cuchar}), 
        c, clen, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_chacha20poly1305_ietf_decrypt(
    m::Bytes, mlen::Ref{UInt64}, nsec::Ptr{Void}, c::Bytes, clen::UInt64, ad::Bytes, adlen::UInt64, npub::Bytes, k::Bytes)

    return ccall(c_crypto_aead_chacha20poly1305_ietf_decrypt, 
        Cint, 
        (Ref{Cuchar}, Ref{Csize_t}, Ptr{Void}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Ref{Cuchar}), 
        m, mlen, nsec, c, clen, ad, adlen, npub, k)
end 

function crypto_aead_xchacha20poly1305_ietf_encrypt(
    c::Bytes, clen::Ref{UInt64}, m::Bytes, mlen::UInt64, ad::Bytes, adlen::UInt64, nsec::Ptr{Void}, npub::Bytes, k::Bytes)

    return ccall(c_crypto_aead_xchacha20poly1305_ietf_encrypt, 
        Cint, 
        (Ref{Cuchar}, Ref{Csize_t}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ptr{Void}, Ref{Cuchar}, Ref{Cuchar}), 
        c, clen, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_xchacha20poly1305_ietf_decrypt(
    m::Bytes, mlen::Ref{UInt64}, nsec::Ptr{Void}, c::Bytes, clen::UInt64, ad::Bytes, adlen::UInt64, npub::Bytes, k::Bytes)

    return ccall(c_crypto_aead_xchacha20poly1305_ietf_decrypt, 
        Cint, 
        (Ref{Cuchar}, Ref{Csize_t}, Ptr{Void}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Ref{Cuchar}), 
        m, mlen, nsec, c, clen, ad, adlen, npub, k)
end 

function crypto_aead_aes256gcm_encrypt(
    c::Bytes, clen::Ref{UInt64}, m::Bytes, mlen::UInt64, ad::Bytes, adlen::UInt64, nsec::Ptr{Void}, npub::Bytes, k::Bytes)

    return ccall(c_crypto_aead_aes256gcm_encrypt, 
        Cint, 
        (Ref{Cuchar}, Ref{Csize_t}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ptr{Void}, Ref{Cuchar}, Ref{Cuchar}), 
        c, clen, m, mlen, ad, adlen, nsec, npub, k)
end

function crypto_aead_aes256gcm_decrypt(
    m::Bytes, mlen::Ref{UInt64}, nsec::Ptr{Void}, c::Bytes, clen::UInt64, ad::Bytes, adlen::UInt64, npub::Bytes, k::Bytes)

    return ccall(c_crypto_aead_aes256gcm_decrypt, 
        Cint, 
        (Ref{Cuchar}, Ref{Csize_t}, Ptr{Void}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Ref{Cuchar}), 
        m, mlen, nsec, c, clen, ad, adlen, npub, k)
end 

# ==================

# ==================
# ===HKDF-SHA1======

function gensubkey(salt::Bytes, masterkey::Bytes, keylen::Integer)
    subkey = Bytes(keylen) 
    err = hkdf_sha1(salt, length(salt), masterkey, keylen, subkey, keylen)
    if err != 0
        return nothing, "Generate Sub Key Error"
    end

    return subkey, nothing
end

const SHA1 = Cint(0)
const INFO = b"ss-subkey"
const INFOLEN = Cint(9)

const hkdf = Libdl.dlopen(joinpath(@__DIR__, "hkdf"))
const c_hkdf = @dlsym("hkdf", hkdf)

function hkdf_sha1(salt::Bytes, saltlen::Integer, ikm::Bytes, ikmlen::Integer, okm::Bytes, okmlen::Integer)
    return ccall(c_hkdf, 
        Cint, 
        (Cint, Ref{Cuchar}, Cint, Ref{Cuchar}, Cint, Ref{Cuchar}, Cint, Ref{Cuchar}, Cint), 
        SHA1, salt, saltlen, ikm, ikmlen, INFO, INFOLEN, okm, okmlen)
end

# ==================

function genkeys(keylen::Csize_t, password::String)
    cnt = Integer(ceil(keylen/MD5Len))
    tmp = Bytes(cnt * MD5Len)

    buff = Bytes(MD5Len + sizeof(password))
    buff[MD5Len+1:end] = Bytes(password)
    md5(buff, Bytes(password))
    tmp[1:MD5Len] = buff[1:MD5Len]

    for i in 2:cnt
        md5(buff, buff)
        tmp[MD5Len * (i-1) + 1 : MD5Len * i] = buff[1:MD5Len]
    end

    return tmp[1:keylen]
end

function read(io::TCPSocket, buff::Bytes)
    try
        eof(io)
    catch err
        return nothing, err
    end

    nbytes = try 
        nb_available(io)
    catch err 
        return nothing, err
    end

    nbytes = nbytes > MaxSize ? MaxSize : nbytes
    try 
        isopen(io) ? readbytes!(io, buff, nbytes) : return nothing, "Connection Closed"
    catch err
        return nothing, err
    end

    return nbytes, nothing
end

function read(io::TCPSocket, buff::Bytes, n::Integer)
    left = n
    ptr = 1

    while left > 0
        isopen(io) || return nothing, "TCPSocket Closed"

        try
            eof(io)
        catch err
            return nothing, err
        end

        nbytes = try 
            nb_available(io)
        catch err
            return nothing, err
        end

        if nbytes >= left
            buff[ptr:ptr + left - 1] = read(io, left)
            break
        else
            buff[ptr:ptr + nbytes - 1] = read(io, nbytes)
            ptr += nbytes
            left -= nbytes
        end
    end

    return n, nothing
end

function write(io::TCPSocket, buff::Bytes, nbytes::Integer)
    try 
        isopen(io) ? write(io, buff[1:nbytes]) : return "Connection Closed"
    catch err 
        return err 
    end

    return nothing
end

function read(ssConn::SSConnection, buff::Bytes)
    nbytes, err = read_stream(ssConn, buff, 2 + ssConn.cipher.taglen)
    if err != nothing
        return nothing, err
    end

    nbytes, err = read_stream(ssConn, buff, UInt16(buff[1]) << 8 + buff[2] + ssConn.cipher.taglen)
    if err != nothing
        return nothing, err
    end

    return nbytes, nothing
end

function write(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    ssConn.tagCache[1:2] = [UInt8(nbytes>>8); UInt8(nbytes&255)]
    err = write_stream(ssConn, ssConn.tagCache, 2)
    if err != nothing
        return err
    end

    err = write_stream(ssConn, buff, nbytes)
    if err != nothing 
        return err
    end

    return nothing
end

function read_stream(ssConn::SSConnection, buff::Bytes, n::Integer)
    nbytes, err = read(ssConn.conn, buff, n)
    if err != nothing
        return nothing, err
    end

    nbytes, err = decrypt(buff, buff, nbytes, ssConn)
    if err != nothing
        return nothing, err
    end

    (++)(ssConn.ivDecrypt)
    return nbytes, nothing
end

function write_stream(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    nbytes, err = encrypt(buff, buff, nbytes, ssConn)
    if err != nothing
        return err
    end

    err = write(ssConn.conn, buff, nbytes)
    if err != nothing
        return err
    end

    (++)(ssConn.ivEncrypt)
    return nothing
end

function encrypt(buff::Bytes, text::Bytes, textlen::Integer, ssConn::SSConnection)
    nbytes = Ref{UInt64}(0)
    err = ssConn.cipher.encrypt(
        buff, nbytes, text, Csize_t(textlen), ssConn.keyEncrypt, Csize_t(0), C_NULL, ssConn.ivEncrypt, ssConn.keyEncrypt)

    if err == -1
        return nothing, err
    end

    return nbytes[], nothing
end

function decrypt(buff::Bytes, ciphertext::Bytes, ciphertextlen::Integer, ssConn::SSConnection)
    nbytes = Ref{UInt64}(0)
    err = ssConn.cipher.decrypt(
        buff, nbytes, C_NULL, ciphertext, Csize_t(ciphertextlen), ssConn.keyDecrypt, Csize_t(0), ssConn.ivDecrypt, ssConn.keyDecrypt)

    if err == -1
        return nothing, err
    end

    return nbytes[], nothing
end

function ioCopy(from::Union{SSConnection, TCPSocket}, to::Union{SSConnection, TCPSocket})
    buff = Bytes(MaxSize + (from isa SSConnection ? from.cipher.taglen : to.cipher.taglen))
    while true
        nbytes, err = read(from, buff)
        if err != nothing
            break
        end

        err = write(to, buff, nbytes)
        if err != nothing
            break
        end
    end
end

function connectRemote(buff::Bytes)
    if !(buff[1] in [0x01; 0x03; 0x04])
        return nothing, "Not a valid CMD"
    end

    host = nothing
    port = nothing

    if buff[1] == 0x01
        host = IPv4(ntoh(unsafe_load(Ptr{UInt32}(pointer(buff[2:5])))))
        port = UInt16(buff[6]) << 8 + buff[7]
    elseif buff[1] == 0x03
        len = buff[2]
        host = String(buff[3:len+2])
        port = UInt16(buff[len+3]) << 8 + buff[len+4]
    elseif buff[1] == 0x04
        host = IPv6(ntoh(unsafe_load(Ptr{UInt128}(pointer(buff[2:17])))))
        port = UInt16(buff[18]) << 8 + buff[19]
    end

    client = try
        connect(host, port)
    catch err
        return nothing, err
    end

    return client, nothing
end

function handleConnection(ssConn::SSConnection)
    client = nothing

    while true
        buff = Bytes(262)

        err = init(ssConn, buff, nothing)
        if err != nothing
            break
        end

        client, err = connectRemote(buff)
        if err != nothing
            break
        end

        buff = nothing
        @async ioCopy(ssConn, client)
        ioCopy(client, ssConn)

        break
    end

    client != nothing && close(client)
    close(ssConn)
end

function handShake(conn::TCPSocket, buff::Bytes)
    nbytes, err = read(conn, buff)
    if err != nothing
        return err
    end

    if buff[1] != 0x05
        return "Not a Socks5 Client"
    end

    if 0x00 in buff[3:nbytes]
        err = write(conn, [0x05; 0x00], 2)
        if err != nothing
            return err
        end
    else 
        err = isopen(conn) && write(conn, [0x05; 0xFF], 2)
        return "Not a Valid Authentication"
    end

    nbytes, err = read(conn, buff, 3)
    if err != nothing
        return err
    end

    if buff[1:3] != [0x05; 0x01; 0x00]
        return "Not a Supported CMD"
    end

    nbytes, err = read(conn, buff)
    if err != nothing
        return err
    end

    if isa(getipaddr(), IPv4)
        err = write(conn, [0x05; 0x00; 0x00; 0x01; 
            0x00; 0x00; 0x00; 0x00; 
            0x00; 0x00], 10)
        if err != nothing
            return err
        end
    else
        err = write(conn, [0x05; 0x00; 0x00; 0x04; 
            0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 
            0x00; 0x00], 22)
        if err != nothing
            return err
        end
    end

    return nbytes
end

function handleConnection(conn::TCPSocket, ssConn::SSConnection)
    while true
        buff = Bytes(262)
        nbytes = handShake(conn, buff)
        if !(nbytes isa Integer)
            break
        end

        err = init(ssConn, buff, nbytes)
        if err != nothing
            break
        end

        buff = nothing
        @async ioCopy(conn, ssConn)
        ioCopy(ssConn, conn)

        break
    end

    close(conn)
    close(ssConn)
end

function runServer(config::SSConfig)
    server = try 
        listen(config.host, config.port)
    catch err
        return
    end

    cipher = Cipher(config)
    err = sodium_init()
    if err < 0
    	return
    end

    while isopen(server)
        conn = accept(server)

        @async handleConnection(
            SSConnection(conn, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Bytes(cipher.taglen + 2), nothing, nothing)
        )
    end
end

function runClient(config::SSConfig)
    server = try
        if isa(getipaddr(), IPv4) 
            listen(IPv4(0), config.lisPort)
        else
            listen(IPv6(0), config.lisPort)
        end
    catch err
        return
    end

    cipher = Cipher(config)
    err = sodium_init()
    if err < 0
    	return 
    end

    while isopen(server)
        conn = accept(server)

        client = try
            connect(config.host, config.port)
        catch err
            close(conn)
            continue
        end

        @async handleConnection(conn, 
            SSConnection(client, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Bytes(cipher.taglen + 2), nothing, nothing)
        )
    end
end

function run(config::SSConfig)
    if config.lisPort == nothing
        runServer(config)
    else
        runClient(config)
    end
end

# =================================

function md5(buff::Bytes, text::Bytes)
    buff[1:MD5Len] = md5(text)
end

# MD5 Function, Copy from JanMD5.jl

mutable struct MD5_CTX
    state::Vector{UInt32}
    bytecount::UInt64
    buffer::Vector{UInt8}
    M::Vector{UInt32}
end

function md5(data::Array{UInt8,1})
    ctx = MD5_CTX()
    update!(ctx, data)
    return digest!(ctx)
end

md5(str::AbstractString) = md5(convert(Array{UInt8,1}, str))
md5(io::IO) = md5(read(io))

digestlen(::Type{MD5_CTX}) = 16
state_type(::Type{MD5_CTX}) = UInt32
blocklen(::Type{MD5_CTX}) = UInt64(64)

const MD5_initial_hash_value = UInt32[
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,]

const S_MD5 = UInt32[
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,]

@assert length(S_MD5) == 64
@assert S_MD5[33] == 4
@assert last(S_MD5) == 21

MD5_CTX() = MD5_CTX(copy(MD5_initial_hash_value), 0, zeros(UInt8, blocklen(MD5_CTX)),
                    zeros(UInt32,16))

import Base.copy
copy(ctx::MD5_CTX) = MD5_CTX(copy(ctx.state), ctx.bytecount, copy(ctx.buffer))

## =============
# stuff copy pasted from Sha.jl

# Common update and digest functions which work across SHA1 and SHA2

# update! takes in variable-length data, buffering it into blocklen()-sized pieces,
# calling transform!() when necessary to update the internal hash state.
function update!(context::MD5_CTX,data)
    T = typeof(context)
    # We need to do all our arithmetic in the proper bitwidth
    UIntXXX = typeof(context.bytecount)

    # Process as many complete blocks as possible
    len = convert(UIntXXX, length(data))
    data_idx = convert(UIntXXX, 0)
    usedspace = context.bytecount % blocklen(T)
    while len - data_idx + usedspace >= blocklen(T)
        # Fill up as much of the buffer as we can with the data given us
        for i in 1:(blocklen(T) - usedspace)
            context.buffer[usedspace + i] = data[data_idx + i]
        end

        transform!(context)
        context.bytecount += blocklen(T) - usedspace
        data_idx += blocklen(T) - usedspace
        usedspace = convert(UIntXXX, 0)
    end

    # There is less than a complete block left, but we need to save the leftovers into context.buffer:
    if len > data_idx
        for i = 1:(len - data_idx)
            context.buffer[usedspace + i] = data[data_idx + i]
        end
        context.bytecount += len - data_idx
    end
end

lrot(b,x,width) = ((x << b) | (x >> (width - b)))
## =============

const K_MD5 = UInt32[floor(UInt32, 2^32 * abs(sin(i))) for i in 1:64]
@assert last(K_MD5) == 0xeb86d391
@assert K_MD5[29] == 0xa9e3e905

# transform!(ctx::MD5_CTX) = transform_baseline!(ctx)
transform!(ctx::MD5_CTX) = transform_unrolled!(ctx)

@generated function transform_unrolled!(context::MD5_CTX)
    ret = quote
        pbuf = Ptr{UInt32}(pointer(context.buffer))
        M = context.M
    end
    for i in 1:16
        ex = :(M[$i] = unsafe_load(pbuf,$i))
        push!(ret.args, ex)
    end
    ex  = quote
        A = context.state[1]
        B = context.state[2]
        C = context.state[3]
        D = context.state[4]
    end
    push!(ret.args, ex)
    for i in 0:63
        if 0 ≤ i ≤ 15
            ex = :(F = (B & C) | ((~B) & D))
            g = i
        elseif 16 ≤ i ≤ 31
            ex = :(F = (D & B) | ((~D) & C))
            g = 5i + 1
        elseif 32 ≤ i ≤ 47
            ex = :(F = B ⊻ C ⊻ D)
            g = 3i + 5
        elseif 48 ≤ i ≤ 63
            ex = :(F = C ⊻ (B | (~D)))
            g = 7i
        end
        push!(ret.args, ex)
        g = (g % 16) + 1
        ex = quote
            temp = D
            D = C
            C = B
            inner = A + F + $(K_MD5[i+1]) + M[$g]
            rot_inner = lrot($(S_MD5[i+1]), inner, 32)
            B = B + rot_inner
            A = temp
        end
        push!(ret.args, ex)
    end

    ex = quote
        context.state[1] += A
        context.state[2] += B
        context.state[3] += C
        context.state[4] += D
    end
    push!(ret.args, ex)
    quote
        @inbounds $ret
    end
end

function transform_baseline!(context::MD5_CTX)
    pbuf = Ptr{UInt32}(pointer(context.buffer))
    for i in 1:16
        context.M[i] = unsafe_load(pbuf,i)
    end
    A = context.state[1]
    B = context.state[2]
    C = context.state[3]
    D = context.state[4]
    for i in 0:63
        if 0 ≤ i ≤ 15
            F = (B & C) | ((~B) & D)
            g = i
        elseif 16 ≤ i ≤ 31
            F = (D & B) | ((~D) & C)
            g = (5i + 1)
        elseif 32 ≤ i ≤ 47
            F = xor(B,C,D)
            g = (3i + 5)
        elseif 48 ≤ i ≤ 63
            F = C ⊻ (B | (~D))
            g = (7i)
        end
        g = g % 16

        temp = D
        D = C
        C = B
        inner = A + F + K_MD5[i+1] + context.M[g+1]
        rot_inner = lrot(S_MD5[i+1], inner, 32)
        B = B + rot_inner
        A = temp
    end

    context.state[1] += A
    context.state[2] += B
    context.state[3] += C
    context.state[4] += D
end

function digest!(context::MD5_CTX)
    T = typeof(context)
    usedspace = context.bytecount % blocklen(T)
    usedspace += 1
    context.buffer[usedspace] = 0x80
    if usedspace <= 56
        while usedspace < 56
            usedspace += 1
            context.buffer[usedspace] = 0x00
        end
    else
        context.buffer[usedspace+1:end] = 0x00
        transform!(context)
        fill!(context.buffer, 0x00)
        usedspace = 56
    end
    @assert usedspace == 56
    B = typeof(context.bytecount)
    bitcount = context.bytecount * B(8)
    pbuf = Ptr{B}(pointer(context.buffer))
    index = 8
    unsafe_store!(pbuf, bitcount, index)
    transform!(context)
    reinterpret(UInt8, context.state)
end

end # module
