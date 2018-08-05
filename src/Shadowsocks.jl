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

function ++(iv::Bytes)
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
    udp::Union{Bool, Void}
end
SSServer(ip, port, method, password) = SSConfig(ip, port, nothing, method, password, nothing)
SSServer() = SSServer(getipaddr() isa IPv4 ? IPv4(0) : IPv6(0), 8388, "CHACHA20-POLY1305-IETF", "imgk0000")
SSClient(ip, port, lisPort, method, password) = SSConfig(ip, port, lisPort, method, password, nothing)
SSClient() = SSClient(getipaddr(), 8388, 1080, "CHACHA20-POLY1305-IETF", "imgk0000")

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

    nybtes isa Integer && begin
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
# ======udp=========
const UDPSize = 65536

macro randPort()
    quote
        UInt16(floor(rand()*10000 + 50000))
    end
end

function doBind(port::Integer)
    udp = UDPSocket()
    try 
        bind(udp, getipaddr() isa IPv4 ? IPv4(0) : IPv6(0), @randPort)
    catch err
        return nothing, err
    end

    return udp, nothing
end

mutable struct S5UDPSocket
    sock::Union{UDPSocket, Void}
end

mutable struct SSUDPSocket
    sock::Union{UDPSocket, Void}
    cipher::Union{Cipher, Void}
    nonce::Union{Bytes, Void}
end

mutable struct NATmap
    map::Dict{Bytes, Union{UDPSocket, SSUDPSocket, Void}}
    timeout::Integer
end

import Base.in
function in(nmap::NATmap, key::Bytes)
    return haskey(nmap.map, key)
end

import Base.send
import Base.recv

function send(sock::SSUDPSocket, ip::IPAddr, port::Integer)
end

function recv(sock::SSUDPSocket)
end

function waitWithTimeout()
end

function gethost(buff::Bytes, shift::Integer)
    host, port = nothing, nothing
    if buff[1+shift] == 0x01
        host = IPv4(ntoh(unsafe_load(Ptr{UInt32}(pointer(buff[2+shift:5+shift])))))
        port = UInt16(buff[6+shift]) << 8 + buff[7+shift]
    elseif buff[1+shift] == 0x03
        len = buff[2+shift]
        host = try
            getaddrinfo(String(buff[3+shift:len+2+shift]))
        catch err
            return nothing, nothing, err
        end
        port = UInt16(buff[len+3+shift]) << 8 + buff[len+4+shift]
    elseif buff[1+shift] == 0x04
        host = IPv6(ntoh(unsafe_load(Ptr{UInt128}(pointer(buff[2+shift:17+shift])))))
        port = UInt16(buff[18+shift]) << 8 + buff[19+shift]
    end

    return host, port, nothing
end

function key(data::Bytes, shift::Integer)
    if data[1+shift] == 0x01
        return data[2+shift:7+shift]
    elseif data[1+shift] == 0x03
        len = data[2+shift]
        return data[3+shift:len+4+shift]
    elseif data[1+shift] == 0x04
        return data[2+shift:19+shift]
    end
end

function udpServer(config::SSConfig, cipher::Cipher)
    udp, err = doBind(config.lisPort)
    server = SSUDPSocket(udp, cipher, zeros(UInt8, cipher.ivlen))
    nmap = NATmap(Dict(UInt8[0,0,0,0,0,0] => nothing), 60)

    while true
        data, err = recv(server)
        begin
            host, port, err = gethost(data, 0)
            thiskey = key(data)
            if thiskey in nmap
            end

            @async waitWithTimeout()
        end
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

include("Crypto.jl")

function crypto_aead_chacha20poly1305_ietf_encrypt(
    c::Bytes, clen::Ref{UInt64}, m::Bytes, mlen::UInt64, ad::Bytes, adlen::UInt64, nsec::Ptr{Void}, npub::Bytes, key::Bytes)

    clen[] = Crypto.Chacha20_IETF_Poly1305_Encrypt(c, key, npub, unsafe_wrap(Array{UInt8}, pointer(m), mlen), UInt8[])

    return nothing
end

function crypto_aead_chacha20poly1305_ietf_decrypt(
    m::Bytes, mlen::Ref{UInt64}, nsec::Ptr{Void}, c::Bytes, clen::UInt64, ad::Bytes, adlen::UInt64, npub::Bytes, key::Bytes)

    mlen[] = Crypto.Chacha20_IETF_Poly1305_Decrypt(m, key, npub, unsafe_wrap(Array{UInt8}, pointer(c), clen), UInt8[])

    return nothing
end 

# ===HKDF-SHA1======
include("HKDF.jl")

const INFO = b"ss-subkey"

function gensubkey(salt::Bytes, masterkey::Bytes, keylen::Integer)
    subkey, err = hkdf_sha1(salt, masterkey, keylen)
    if err != nothing
        return nothing, "Generate Sub Key Error"
    end

    return subkey, nothing
end

function hkdf_sha1(salt::Bytes, ikm::Bytes, okmlen::Integer)
	return HKDF.hkdf("SHA1", salt, ikm, INFO, okmlen), nothing
end
# ==================

# ========MD5=========

include("MD5.jl")

function md5(buff::Bytes, text::Bytes)
    buff[1:MD5Len] = MD5.md5(text)
end

# ====================


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

    ++(ssConn.ivDecrypt)
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

    ++(ssConn.ivEncrypt)
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

function gethost(buff::Bytes)
    host, port = nothing, nothing
    if buff[1] == 0x01
        host = IPv4(ntoh(unsafe_load(Ptr{UInt32}(pointer(buff[2:5])))))
        port = UInt16(buff[6]) << 8 + buff[7]
    elseif buff[1] == 0x03
        len = buff[2]
        host = try
            getaddrinfo(String(buff[3:len+2]))
        catch err
            return nothing, nothing, err
        end
        port = UInt16(buff[len+3]) << 8 + buff[len+4]
    elseif buff[1] == 0x04
        host = IPv6(ntoh(unsafe_load(Ptr{UInt128}(pointer(buff[2:17])))))
        port = UInt16(buff[18]) << 8 + buff[19]
    end

    return host, port, nothing
end

function connectRemote(buff::Bytes)
    if !(buff[1] in [0x01; 0x03; 0x04])
        return nothing, "Not a valid CMD"
    end

    host, port, err = gethost(buff)
    if err != nothing
        return nothing, err
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

function tcpServer(config::SSConfig, cipher::Cipher)
    server = try 
        listen(config.host, config.port)
    catch err
        return
    end

    while isopen(server)
        conn = accept(server)

        @async handleConnection(
            SSConnection(conn, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Bytes(cipher.taglen + 2), nothing, nothing)
        )
    end
end

function runServer(config::SSConfig)
    cipher = Cipher(config)

    tcpServer(config, cipher)
end

function tcpClient(config::SSConfig, cipher::Cipher)
    server = try
        if isa(getipaddr(), IPv4) 
            listen(IPv4(0), config.lisPort)
        else
            listen(IPv6(0), config.lisPort)
        end
    catch err
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

function runClient(config::SSConfig)
    cipher = Cipher(config)

    tcpClient(config, cipher)
end

function run(config::SSConfig)
    if config.lisPort == nothing
        runServer(config)
    else
        runClient(config)
    end
end

end # module
