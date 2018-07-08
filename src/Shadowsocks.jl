__precompile__(false)

module Shadowsocks

# package code goes here

export SSServer, SSClient, run

using MD5 # https://github.com/oxinabox/MD5.jl.git
using AES # https://github.com/faf0/AES.jl.git
using LegacyStrings # https://github.com/JuliaStrings/LegacyStrings.jl.git
using SHA # https://github.com/staticfloat/SHA.jl.git

import Base.run

const Bytes = Array{UInt8}
const CODESET = Bytes("1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm")
const METHOD = Dict{String, Dict{String, Integer}}(
    "AES-256-CFB" => Dict{String, Integer}("KEYLEN" => 32, "IVLEN" => 16)
)

macro GenPass()
    return :(String(rand(CODESET, 16)))
end

macro ToPort(p)
    return :(hex2bytes(num2hex($p))[end-1:1:end])
end

function toPort(p)
    return hex2bytes(num2hex(p))[end-1:1:end]
end

macro ToIP(ip)
    return :(hex2bytes(num2hex(($ip).host)))
end

function toIP(ip)
    return hex2bytes(num2hex(ip.host))
end

mutable struct SSConfig
    host::IPAddr
    port::Integer
    listen::Union{Integer, Bool}
    method::String
    password::String
end
SSServer(ip, port, method, password) = SSConfig(ip, port, false, method, password)
SSServer() = SSServer(getipaddr(), 8088, "AES-256-CFB", "imgk0000")
SSClient(ip, port, listen, method, password) = SSConfig(ip, port, listen, method, password)
SSClient() = SSConfig(getipaddr(), 8088, 1080, "AES-256-CFB", "imgk0000")

mutable struct Cipher
    method::String
    key::Bytes
    iv1::Bytes
    iv2::Bytes
    encrypt::Function
    decrypt::Function
end
Cipher() = Cipher(
    "AES-256-CFB", 
    [0x00; ], 
    [0x00; ],
    [0x00; ],
    () -> nothing, 
    () -> nothing
)

mutable struct SSConn
    conn::TCPSocket
    cipher::Cipher
end
SSConn() = SSConn(TCPSocket(), Cipher())

function getkeys(method::String, str::String)
    const md5len = 16

    password = Bytes(str)
    keylen = METHOD[method]["KEYLEN"]

    cnt = Integer(floor((keylen-1)/md5len)) + 1
    m = Bytes(cnt * md5len)
    
    md5hash = md5(password)
    m[1:md5len] = md5hash

    for i in 2:1:cnt
        md5hash = md5([md5hash; password])
        m[md5len * (i-1) + 1 : md5len * i] = md5hash
    end
    return m[1:keylen]
end

function parseCipher(config::SSConfig)
    cipher = Cipher()
    cipher.method = config.method
    cipher.key = getkeys(cipher.method, config.password)
    cipher.iv1 = rand(UInt8, METHOD[config.method]["IVLEN"])
    cipher.iv2 = rand(UInt8, METHOD[config.method]["IVLEN"])

    config.method == "AES-256-CFB" && begin
        cipher.encrypt = (buff::Bytes, key::Bytes, iv::Bytes) -> AESCFB(buff, key, iv, true)
        cipher.decrypt = (buff::Bytes, key::Bytes, iv::Bytes) -> AESCFB(buff, key, iv, false)
        return cipher, nothing
    end
end

function safe_read(io::TCPSocket, buff::Bytes)
    try
        eof(io)
    catch err
        return nothing, err
    end

    nbytes = nb_available(io)
    isa(nbytes, Integer) && if nbytes != 0
        try 
            readbytes!(io, buff, nbytes)
        catch err
            return nothing, err
        end

        return nbytes, nothing
    end

    return nothing, ""
end

function decrypt(buff::Bytes, cipher::Cipher)
    if cipher.method == "AES-256-CFB"
        data = try 
            cipher.decrypt(buff, cipher.key, cipher.iv1)
        catch err
            return nothing, err
        end
    end

    return data, nothing
end

function encrypt(buff::Bytes, cipher::Cipher)
    if cipher.method == "AES-256-CFB"
        data = try 
            cipher.encrypt(buff, cipher.key, cipher.iv2)
        catch err
            return nothing, err
        end
    end

    return data, nothing
end

function parseHost(payload::Bytes)
    if !(payload[1] in [0x01; 0x03; 0x04])
        return nothing, nothing, ""
    end

    host = nothing
    port = nothing

    payload[1] == 0x01 && begin
        host = IPv4(Integer(payload[2]), Integer(payload[3]), Integer(payload[4]), Integer(payload[5]))
        port = Integer(payload[6]) * Integer(256) + Integer(payload[7])
    end

    payload[1] == 0x03 && begin
        len = Integer(payload[2])
        host = String(payload[3:len+2])
        port = Integer(payload[len+3]) * Integer(256) + Integer(payload[len+4])
    end

    payload[1] == 0x04 && begin
        host = IPv6(Integer(payload[2]) * Integer(256) + Integer(payload[3]),
            Integer(payload[4]) * Integer(256) + Integer(payload[5]),
            Integer(payload[6]) * Integer(256) + Integer(payload[7]),
            Integer(payload[8]) * Integer(256) + Integer(payload[9]),
            Integer(payload[10]) * Integer(256) + Integer(payload[11]),
            Integer(payload[12]) * Integer(256) + Integer(payload[13]),
            Integer(payload[14]) * Integer(256) + Integer(payload[15]),
            Integer(payload[16]) * Integer(256) + Integer(payload[17]))
        port = Integer(payload[18]) * Integer(256) + Integer(payload[19])
    end

    return host, port, nothing
end

function connectRemote(payload::Bytes)
    host, port, err = parseHost(payload)
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

function handleConnection(ssConn::SSConn)
    buff = Bytes(1024)

    nbytes, err = safe_read(ssConn.conn, buff)
    if err != nothing
        close(ssConn.conn)
        return
    end

    const ivlen = METHOD[ssConn.cipher.method]["IVLEN"]
    ssConn.cipher.iv1 = buff[1:ivlen]
    payload, err = decrypt(buff[ivlen+1:nbytes], ssConn.cipher)
    if err != nothing
        close(ssConn.conn)
        return
    end

    client, err = connectRemote(payload)
    if err != nothing
        close(ssConn.conn)
        return
    end

    ssConn.cipher.iv2 = rand(UInt8, ivlen)
    isopen(ssConn.conn) && write(ssConn.conn, ssConn.cipher.iv2)

    buff = nothing
    @async begin
        buff_in = Bytes(65536)
        while isopen(ssConn.conn) && isopen(client)
            nbytes, err = safe_read(ssConn.conn, buff_in)
            if err != nothing
                continue
            end

            data, err = decrypt(buff_in[1:nbytes], ssConn.cipher)
            if err != nothing
                continue
            end

            isopen(client) && write(client, data)
        end

        close(client)
        close(ssConn.conn)
    end

    begin
        buff_out = Bytes(65536)
        while isopen(ssConn.conn) && isopen(client)
            nbytes, err = safe_read(client, buff_out)
            if err != nothing
                continue
            end

            data, err = encrypt(buff_out[1:nbytes], ssConn.cipher)
            if err != nothing
                continue
            end

            isopen(ssConn.conn) && write(ssConn.conn, data)
        end

        close(client)
        close(ssConn.conn)
    end
end

function handShake(conn::TCPSocket)
    buff = Bytes(1024)
    nbytes, err = safe_read(conn, buff)
    if err != nothing
        return false
    end

    if buff[1] != 0x05
        return false
    end

    if 0x00 in buff[3:end]
        write(conn, [0x05; 0x00])
        return true
    else 
        write(conn, [0x05; 0xFF])
        return false
    end

    return false
end

function getRequest(conn::TCPSocket)
    buff = Bytes(1024)
    nbytes, err = safe_read(conn, buff)
    if err != nothing
        return nothing, err
    end

    return buff[4:nbytes], nothing
end

function handleConnection(conn::TCPSocket, config::SSConfig)
    handShake(conn) || begin 
        close(conn) 
        return
    end

    req, err = getRequest(conn)
    if err != nothing 
        close(conn)
        return
    end

    cipher, err = parseCipher(config)
    if err != nothing
        return
    end

    client = try
        connect(config.host, config.port)
    catch err
        close(conn)
        return
    end

    isopen(conn) && write(conn, [0x05; 0x00; 0x00; 0x01; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00])
    ssConn = SSConn(client, cipher)

    data, err = encrypt(req, ssConn.cipher)
    if err != nothing
        close(ssConn.conn)
        close(conn)
        return
    end

    isopen(ssConn.conn) && write(ssConn.conn, [ssConn.cipher.iv2; data])

    buff = Bytes(1024)
    nbytes, err = safe_read(ssConn.conn, buff)
    if err != nothing
        close(ssConn.conn)
        close(conn)
        return
    end

    const ivlen = METHOD[ssConn.cipher.method]["IVLEN"]
    ssConn.cipher.iv1 = buff[1:ivlen]

    if ivlen != nbytes
    end

    buff = nothing
    @async begin
        buff_in = Bytes(65536)
        while isopen(conn) && isopen(ssConn.conn)
            nbytes, err = safe_read(conn, buff_in)
            if err != nothing
                continue
            end

            data, err = encrypt(buff_in[1:nbytes], ssConn.cipher)
            if err != nothing
                continue
            end

            isopen(ssConn.conn) && write(ssConn.conn, data)
        end

        close(conn)
        close(ssConn.conn)
    end

    begin
        buff_out = Bytes(65536)
        while isopen(ssConn.conn) && isopen(conn)
            nbytes, err = safe_read(ssConn.conn, buff_out)
            if err != nothing
                continue
            end

            data, err = decrypt(buff_out[1:nbytes], ssConn.cipher)
            if err != nothing
                continue
            end

            isopen(conn) && write(conn, data)
        end

        close(conn)
        close(ssConn.conn)
    end
end

function run(config::SSConfig)

    config.listen == false && begin 
        server = try 
            listen(config.host, config.port)
        catch err
            return
        end

        cipher, err = parseCipher(config)
        if err != nothing
            return
        end

        while isopen(server)
            conn = accept(server)
            @async handleConnection(SSConn(conn, cipher))
        end
    end

    isa(config.listen, Integer) && begin 
        server = try
            listen(getipaddr(), config.listen)
        catch err
            return
        end

        while isopen(server)
            conn = accept(server)
            @async handleConnection(conn, config)
        end
    end
end


end # module
