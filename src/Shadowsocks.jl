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
#
module Shadowsocks

export SSServer, SSClient, run

using Sockets
using Dates
using JSON

include("Crypto.jl")

import Base.run
import Base.read
import Base.write
import Base.isopen
import Base.close

const Bytes = Array{UInt8}
const MaxSize = 0x3FFF
const MD5Len = 16
const INFO = Array{UInt8}("ss-subkey")
const METHOD = Dict{String, Dict{String, Integer}}(
    "CHACHA20-POLY1305-IETF" => Dict{String, Integer}("KEYLEN" => UInt64(32), "TAGLEN" => UInt64(16), "IVLEN" => UInt64(12)),
    "XCHACHA20-POLY1305-IETF" => Dict{String, Integer}("KEYLEN" => UInt64(32), "TAGLEN" => UInt64(16), "IVLEN" => UInt64(24))
)

macro terminal(message)
    quote
        println(stdout, Dates.now(), " : ", $(esc(message)))
    end
end

@inline function ++(iv::Bytes)
    for i in 1:length(iv)
        iv[i] += 0x01
        if iv[i] != 0x00
            break
        end
    end
end

mutable struct SSConfig
    host::Sockets.IPAddr
    port::Integer
    lisPort::Union{Integer, Nothing}
    method::String
    password::String
    udp::Union{Bool, Nothing}
end
SSServer(ip, port, method, password) = SSConfig(ip, port, nothing, method, password, nothing)
SSClient(ip, port, lisPort, method, password) = SSConfig(ip, port, lisPort, method, password, nothing)

mutable struct Cipher
    method::Union{String, Nothing}
    key::Union{Bytes, Nothing}
    keylen::UInt64
    ivlen::UInt64
    taglen::Union{Integer, Nothing}
    encrypt::Union{Function, Nothing}
    decrypt::Union{Function, Nothing}
end
function Cipher(config::SSConfig)
    cipher = Cipher(
        config.method,
        genkey(METHOD[config.method]["KEYLEN"], config.password),
        METHOD[config.method]["KEYLEN"],
        METHOD[config.method]["IVLEN"],
        METHOD[config.method]["TAGLEN"],
        nothing,
        nothing)

    if config.method == "CHACHA20-POLY1305-IETF"
        cipher.encrypt = Crypto.Chacha20_Poly1305_IETF.Encrypt
        cipher.decrypt = Crypto.Chacha20_Poly1305_IETF.Decrypt
    elseif config.method == "XCHACHA20-POLY1305-IETF"
        cipher.encrypt = Crypto.XChacha20_Poly1305_IETF.Encrypt
        cipher.decrypt = Crypto.XChacha20_Poly1305_IETF.Decrypt
    end

    return cipher
end

mutable struct SSConnection
    conn::Union{TCPSocket, Nothing}
    cipher::Union{Cipher, Nothing}
    ivDecrypt::Union{Bytes, Nothing}
    ivEncrypt::Union{Bytes, Nothing}
    tagCache::Union{Bytes, Nothing}
    keyDecrypt::Union{Bytes, Nothing}
    keyEncrypt::Union{Bytes, Nothing}
end

@inline function close(ssConn::SSConnection)
    return close(ssConn.conn)
end

@inline function isopen(ssConn::SSConnection)
    return isopen(ssConn.conn)
end

@inline function init_read(ssConn::SSConnection, buff::Bytes) # Server
    saltlen = max(16, ssConn.cipher.keylen)

    salt = Bytes(undef, saltlen)
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

    return nothing
end

@inline function init_write(ssConn::SSConnection) # Server
    saltlen = max(16, ssConn.cipher.keylen)

    salt = rand(UInt8, saltlen)
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

@inline function init_read(ssConn::SSConnection) # Client
    saltlen = max(16, ssConn.cipher.keylen)

    salt = Bytes(undef, saltlen)
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

@inline function init_write(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    saltlen = max(16, ssConn.cipher.keylen)

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
    
    return nothing
end

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
    sock::Union{UDPSocket, Nothing}
end

mutable struct SSUDPSocket
    sock::Union{UDPSocket, Nothing}
    cipher::Union{Cipher, Nothing}
    nonce::Union{Bytes, Nothing}
end

mutable struct NATmap
    map::Dict{Bytes, Union{UDPSocket, SSUDPSocket, Nothing}}
    timeout::Integer
end

import Base.in
function in(nmap::NATmap, key::Bytes)
    return haskey(nmap.map, key)
end

import Sockets.send
import Sockets.recv

function send(sock::SSUDPSocket, ip::Sockets.IPAddr, port::Integer)
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
# =====udp==========

# ====SIP002========
# "ss://chacha20-poly1305-ietf:imgk0000@192.168.0.1:8388"
# "ss://chacha20-poly1305-ietf:imgk0000@:8388"
function parseURI(text::String)
    if text[1:5] != "ss://"
        return nothing, "Invalid Config"
    end

    r = match(r"ss://(?<method>[\w-]+):(?<password>\w+)@(?<ip>[0-9\.]*):(?<port>\d+)", text)

    if r["ip"] == ""
        return SSServer(getipaddr(), parse(UInt16, r["port"]), uppercase(r["method"]), r["password"]), nothing
    else
        return SSClient(parse(Sockets.IPAddr, r["ip"]), parse(UInt16, r["port"]), 1080, uppercase(r["method"]), r["password"]), nothing
    end
end

# =====JSON=Config=File====
# {
#     "Server1":{
#         "host":"0.0.0.0",
#         "port":8388,
#         "method":"chacha20-poly1305-ietf",
#         "password":"imgk0000"
#     },
#     "Server2":{
#         "host":"0.0.0.0",
#         "port":8388,
#         "method":"chacha20-poly1305-ietf",
#         "password":"imgk0000"
#     }
# }

# {
#     "lisPort":1080,
#     "Server1":{
#         "host":"0.0.0.0",
#         "port":8388,
#         "method":"chacha20-poly1305-ietf",
#         "password":"imgk0000"
#     },
#     "Server2":{
#         "host":"0.0.0.0",
#         "port":8388,
#         "method":"chacha20-poly1305-ietf",
#         "password":"imgk0000"
#     }
# }
function readConfigFile(file::String)
    conf = JSON.parsefile(file)
    
    if haskey(conf, "listenPort")
        port = conf["listenPort"]
        delete!(conf, "listenPort")
        array = Array{SSConfig}(undef, length(conf))
        i = 1
        for (k, v) in conf
            array[i] = SSClient(
                parse(Sockets.IPAddr, v["host"]), 
                v["port"], 
                port, 
                uppercase(v["method"]), 
                v["password"]
            )
            i += 1
        end

        return array
    else
        for (k, v) in conf
            conf[k] = SSServer(
                parse(Sockets.IPAddr, v["host"]), 
                v["port"], 
                uppercase(v["method"]), 
                v["password"]
            )
        end
        return conf
    end
end

@inline function gensubkey(salt::Bytes, masterkey::Bytes, keylen::Integer)
    subkey, err = Crypto.HKDF.hkdf("SHA1", salt, masterkey, INFO, keylen)
    if err != nothing
        return nothing, "Generate Sub Key Error"
    end

    return subkey, nothing
end

@inline function genkey(keylen::UInt64, password::String)
    cnt = fld(keylen, MD5Len)
    left = keylen % MD5Len
    tmp = Bytes(undef, cnt * MD5Len + left)
    
    len = sizeof(password)
    buff = Bytes(undef, MD5Len + len)
    pass = unsafe_wrap(Bytes, pointer(password), len)
    buff[MD5Len + 1 : end] = pass
    buff[1 : MD5Len] = Crypto.MD5.md5(pass)
    tmp[1 : MD5Len] = buff[1 : MD5Len]

    for i in 2 : cnt
        buff[1 : MD5Len] = Crypto.MD5.md5(buff)
        tmp[MD5Len * (i-1) + 1 : MD5Len * i] = buff[1 : MD5Len]
    end

    tmp[MD5Len * cnt + 1 : MD5Len * cnt + left] = Crypto.MD5.md5(buff)[1 : left]

    return tmp
end

@inline function read(io::TCPSocket, buff::Bytes)
    try
        eof(io)
    catch err
        return nothing, err
    end

    nbytes = try 
        bytesavailable(io)
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

@inline function read(io::TCPSocket, buff::Bytes, nbyte::Integer)
    left = nbyte
    ptr = pointer(buff)

    while left > 0
        try
            eof(io)
        catch err
            return nothing, err
        end

        nbytes = try 
            bytesavailable(io)
        catch err
            return nothing, err
        end

        if nbytes >= left
            isopen(io) ? unsafe_read(io, ptr, left) : return nothing, "Connection Closed"
            break
        else
            isopen(io) ? unsafe_read(io, ptr, nbytes) : return nothing, "Connection Closed"
            ptr += nbytes
            left -= nbytes
        end
    end

    return nbyte, nothing
end

@inline function write(io::TCPSocket, buff::Bytes, nbytes::Integer)
    try 
        isopen(io) ? write(io, unsafe_wrap(Array{UInt8}, pointer(buff), nbytes)) : return "Connection Closed"
    catch err 
        return err 
    end

    return nothing
end

@inline function read(ssConn::SSConnection, buff::Bytes)
    nbytes, err = read_stream(ssConn, buff, 2 + ssConn.cipher.taglen)
    if err != nothing
        return nothing, err
    end
    ++(ssConn.ivDecrypt)

    nbytes, err = read_stream(ssConn, buff, UInt16(buff[1]) << 8 + buff[2] + ssConn.cipher.taglen)
    if err != nothing
        return nothing, err
    end
    ++(ssConn.ivDecrypt)

    return nbytes, nothing
end

@inline function write(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    ssConn.tagCache[1:2] = [UInt8(nbytes >> 8); UInt8(nbytes & 0xff)]
    err = write_stream(ssConn, ssConn.tagCache, 2)
    if err != nothing
        return err
    end
    ++(ssConn.ivEncrypt)

    err = write_stream(ssConn, buff, nbytes)
    if err != nothing 
        return err
    end
    ++(ssConn.ivEncrypt)

    return nothing
end

@inline function read_stream(ssConn::SSConnection, buff::Bytes, n::Integer)
    nbytes, err = read(ssConn.conn, buff, n)
    if err != nothing
        return nothing, err
    end

    nbytes, err = ssConn.cipher.decrypt(buff, ssConn.keyDecrypt, ssConn.ivDecrypt, unsafe_wrap(Array{UInt8}, pointer(buff), nbytes), UInt8[])
    if err != nothing
        return nothing, err
    end

    return nbytes, nothing
end

@inline function write_stream(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    nbytes, err = ssConn.cipher.encrypt(buff, ssConn.keyEncrypt, ssConn.ivEncrypt, unsafe_wrap(Array{UInt8}, pointer(buff), nbytes), UInt8[])
    if err != nothing
        return err
    end

    err = write(ssConn.conn, buff, nbytes)
    if err != nothing
        return err
    end

    return nothing
end

function ioCopy(from::Union{SSConnection, TCPSocket}, to::Union{SSConnection, TCPSocket})
    buff = Bytes(undef, MaxSize + (from isa SSConnection ? from.cipher.taglen : to.cipher.taglen))
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

@inline function gethost(buff::Bytes)
    host, port = nothing, nothing
    if buff[1] == 0x01
        host = IPv4(ntoh(unsafe_load(Ptr{UInt32}(pointer(buff) + 1))))
        port = UInt16(buff[6]) << 8 | buff[7]
    elseif buff[1] == 0x03
        len = buff[2]
        host = try
            getaddrinfo(String(unsafe_wrap(Array{UInt8}, pointer(buff) + 2, len)))
        catch err
            return nothing, nothing, err
        end
        port = UInt16(buff[len+3]) << 8 | buff[len+4]
    elseif buff[1] == 0x04
        host = IPv6(ntoh(unsafe_load(Ptr{UInt128}(pointer(buff) + 1))))
        port = UInt16(buff[18]) << 8 | buff[19]
    end

    return host, port, nothing
end

@inline function connectRemote(buff::Bytes)
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

@inline function handleConnection(ssConn::SSConnection) # Server
    remote = nothing

    while true
        buff = Bytes(undef, 262)

        err = init_read(ssConn, buff)
        if err != nothing
            break
        end

        remote, err = connectRemote(buff)
        if err != nothing
            break
        end

        @async ioCopy(ssConn, remote)

        err = init_write(ssConn)
        if err != nothing
            break
        end

        buff = nothing
        ioCopy(remote, ssConn)

        break
    end

    remote != nothing && close(remote)
    close(ssConn)
end

@inline function handShake(conn::TCPSocket, buff::Bytes)
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
        err = write(conn, [0x05; 0xFF], 2)
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

    if getipaddr() isa IPv4
        err = write(conn, [0x05; 0x00; 0x00; 0x01; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00], 10)
        if err != nothing
            return err
        end
    else
        err = write(conn, [0x05; 0x00; 0x00; 0x04; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00], 22)
        if err != nothing
            return err
        end
    end

    return nbytes
end

@inline function handleConnection(conn::TCPSocket, ssConn::SSConnection) # Client
    while true
        buff = Bytes(undef, 262)
        nbytes = handShake(conn, buff)
        if !(nbytes isa Integer)
            break
        end

        err = init_write(ssConn, buff, nbytes)
        if err != nothing
            break
        end

        @async ioCopy(conn, ssConn)

        err = init_read(ssConn)
        if err != nothing
            break
        end

        buff = nothing
        ioCopy(ssConn, conn)

        break
    end

    close(conn)
    close(ssConn)
end

@inline function tcpServer(config::SSConfig, cipher::Cipher)
    server = try 
        listen(config.host, config.port)
    catch err
        return
    end

    while isopen(server)
        conn = try
            accept(server)
        catch err
            break
        end

        @async handleConnection(
            SSConnection(conn, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Bytes(undef, cipher.taglen + 2), nothing, nothing)
        )
    end

    close(server)
end

@inline function tcpServer(config::SSConfig, cipher::Cipher, terminate::Condition)
    server = try 
        listen(config.host, config.port)
    catch err
        return
    end

    @async while isopen(server)
        conn = try
            accept(server)
        catch err
            break
        end

        @async handleConnection(
            SSConnection(conn, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Bytes(undef, cipher.taglen + 2), nothing, nothing)
        )
    end

    wait(terminate)
    close(server)
end

@inline function runServer(config::SSConfig)
    cipher = Cipher(config)

    # @async udpServer()
    tcpServer(config, cipher)
end

@inline function runServer(config::SSConfig, terminate::Condition)
    cipher = Cipher(config)

    # @async udpServer()
    tcpServer(config, cipher, terminate)
end

@inline function tcpClient(config::SSConfig, cipher::Cipher)
    server = try
        listen(getipaddr() isa IPv4 ? IPv4(0) : IPv6(0), config.lisPort)
    catch err
        return
    end

    while isopen(server)
        conn = try
            accept(server)
        catch err
            break
        end

        client = try
            connect(config.host, config.port)
        catch err
            close(conn)
            continue
        end

        @async handleConnection(
            conn, 
            SSConnection(client, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Bytes(undef, cipher.taglen + 2), nothing, nothing)
        )
    end

    close(server)
end

@inline function tcpClient(configs::Array{SSConfig}, ciphers::Array{Cipher})
    server = try
        listen(getipaddr() isa IPv4 ? IPv4(0) : IPv6(0), configs[1].lisPort)
    catch err
        return
    end

    nServers = [1:length(configs)...]

    while isopen(server)
        conn = try
            accept(server)
        catch err
            break
        end

        n = rand(nServers, 1)
        cipher = ciphers[n]
        config = configs[n]

        client = try
            connect(config.host, config.port)
        catch err
            close(conn)
            continue
        end

        @async handleConnection(
            conn, 
            SSConnection(client, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Bytes(undef, cipher.taglen + 2), nothing, nothing)
        )
    end

    close(server)
end

@inline function runClient(config::SSConfig)
    cipher = Cipher(config)

    # @async udpClient()
    tcpClient(config, cipher)
end

@inline function runClient(configs::Array{SSConfig})
    ciphers = Cipher.(configs)

    # @async udpclient()
    tcpClient(configs, ciphers)
end

function run(config::SSConfig, isServer::Bool)
    if isServer
        runServer(config)
    else
        runClient(config)
    end
end

function run(configs::Array{SSConfig}) # configure multi servers at client side
    runClient(configs)
end

function run(ch::Channel{Dict{String, Any}}) # configure multi servers at server side
    servers = Dict{String, Condition}()

    while true
        configs = take!(ch)

        key = keys(servers) # add server
        for (k, v) in configs
            if !(k in key)
                servers[k] = Condition()
                @async runServer(v, servers[k])
            end
        end

        key = keys(configs) # disable server
        for (k, ~) in servers
            if !(k in key)
                notify(servers[k])
                delete!(servers, k)
            end
        end
    end
end

end # module
