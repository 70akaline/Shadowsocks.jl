__precompile__(false)

module Shadowsocks

# package code goes here

export SSServer, run

using MD5
using AES

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

mutable struct SSServer
    host::IPAddr
    port::Integer
    method::String
    password::String
end
SSServer() = SSServer(getipaddr(), 8088, "AES-256-CFB", "imgk0000")

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

function parseCipher(config::SSServer)
    cipher = Cipher()
    cipher.method = config.method

    config.method == "AES-256-CFB" && begin
        cipher.key = getkeys(cipher.method, config.password)
        cipher.encrypt = (buff::Bytes, key::Bytes, iv::Bytes) -> AESCFB(buff, key, iv, true)
        cipher.decrypt = (buff::Bytes, key::Bytes, iv::Bytes) -> AESCFB(buff, key, iv, false)
        return cipher, nothing
    end
end

function safe_read(io::TCPSocket, buff::Bytes)
    try
        eof(io)
    catch err
        return "", err
    end

    nbytes = nb_available(io)
    isa(nbytes, Integer) && if nbytes != 0
        try 
            readbytes!(io, buff, nbytes)
        catch err
            return "", err
        end

        return nbytes, nothing
    end

    return "", ""
end

function decrypt(buff::Bytes, cipher::Cipher)
    if cipher.method == "AES-256-CFB"
        data = try 
            cipher.decrypt(buff, cipher.key, cipher.iv1)
        catch err
            return "", err
        end
    end

    return data, nothing
end

function encrypt(buff::Bytes, cipher::Cipher)
    if cipher.method == "AES-256-CFB"
        data = try 
            cipher.encrypt(buff, cipher.key, cipher.iv2)
        catch err 
            return "", err
        end
    end

    return data, nothing
end

function handShake(payload::Bytes)
    if !(payload[1] in [0x01; 0x03; 0x04])
        return "", "", "", ""
    end

    host = nothing
    port = nothing

    payload[1] == 0x01 && begin
        host = IPv4(Integer(payload[2]), Integer(payload[3]), Integer(payload[4]), Integer(payload[5]))
        port = Integer(payload[6]) * Integer(256) + Integer(payload[7])
        data = payload[8:end]
        return host, port, data, nothing
    end

    payload[1] == 0x03 && begin
        len = Integer(payload[2])
        host = String(payload[3:len+2])
        port = Integer(payload[len+3]) * Integer(256) + Integer(payload[len+4])
        data = payload[len+5:end]
        return host, port, data, nothing
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
        data =payload[20:end]
        return host, port, data, nothing
    end
end

function handleConnection(ssConn::SSConn)
    buff = Bytes(65536)

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

    host, port, data, err = handShake(payload)
    if err != nothing
        close(ssConn.conn)
        return
    end

    client = try
        connect(host, port)
    catch err
        close(ssConn.conn)
        return
    end

    isopen(client) && write(client, data)

    nbytes, err = safe_read(client, buff)
    if err != nothing
        close(client)
        close(ssConn.conn)
        return
    end

    ssConn.cipher.iv2 = rand(UInt8, length(ssConn.cipher.iv2))
    data, err = encrypt(buff[1:nbytes], ssConn.cipher)
    isopen(ssConn.conn) && write(ssConn.conn, [ssConn.cipher.iv2; [0x01, ]; toIP(getipaddr()); toPort(0); data])

    @async begin
        buff_in = buff

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

function run(config::SSServer)
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


end # module
