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

# package code goes here

export SSServer, SSClient, run

import Base.run
import Base.read
import Base.write

# include("libShadowsocks.jl")
const Bytes     = Array{UInt8}
const CodeSet   = Bytes("1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm")
const libcrypto = Libdl.dlopen(joinpath(Pkg.dir("Shadowsocks"), "libs", "libcrypto"))
const METHOD    = Dict{String, Dict{String, Integer}}(
    "CHACHA20-POLY1305"       => Dict{String, Integer}("TYPE" => Cuchar(1), "KEYLEN" => 32, "IVLEN" => 8),
    "CHACHA20-POLY1305-IETF"  => Dict{String, Integer}("TYPE" => Cuchar(2), "KEYLEN" => 32, "IVLEN" => 12),
    "XCHACHA20-POLY1305-IETF" => Dict{String, Integer}("TYPE" => Cuchar(3), "KEYLEN" => 32, "IVLEN" => 24),
    "AES-256-GCM"             => Dict{String, Integer}("TYPE" => Cuchar(4), "KEYLEN" => 32, "IVLEN" => 12)
)

macro GenPass(len)
    quote
    	String(rand(CodeSet, $len))
    end
end

macro ToPort(p)
    quote
        hex2bytes(num2hex($p))[end-1:1:end]
    end
end

function toPort(p)
    return hex2bytes(num2hex(p))[end-1:1:end]
end

macro ToIP(ip)
    quote
        hex2bytes(num2hex(($ip).host))
    end
end

function toIP(ip)
    return hex2bytes(num2hex(ip.host))
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

const md5hash   = @dlsym("md5hash", libcrypto)
const encryptor = @dlsym("encrypt", libcrypto)
const decryptor = @dlsym("decrypt", libcrypto)

macro Md5(buff, text)
    quote
        ccall(md5hash, Int64, (Ref{Cuchar}, Ref{Cuchar}, Csize_t), $buff, Array{Cuchar}($text), Csize_t(sizeof($text)))
    end
end

function md5(buff, text)
    return ccall(md5hash, Int64, (Ref{Cuchar}, Ref{Cuchar}, Csize_t), buff, Array{Cuchar}(text), Csize_t(sizeof(text)))
end

mutable struct SSConfig
    host::IPAddr
    port::Integer
    lisPort::Union{Integer, Bool}
    method::String
    password::String
end
SSServer(ip, port, method, password) = SSConfig(ip, port, false, method, password)
SSServer() = SSServer(getipaddr(), 8088, "CHACHA20-POLY1305", "imgk0000")
SSClient(ip, port, lisPort, method, password) = SSConfig(ip, port, lisPort, method, password)
SSClient() = SSConfig(getipaddr(), 8088, 1080, "CHACHA20-POLY1305", "imgk0000")

mutable struct Cipher
    method::String
    add_text::Bytes
    add_text_len::Csize_t
    key::Bytes
    deiv::Bytes
    eniv::Bytes
    ctype::Cuchar
end
Cipher() = Cipher(
    "method", 
    [0x00; ], 
    Csize_t(0),
    [0x00; ],
    [0x00; ],
    [0x00; ],
    Cuchar(0)
)

mutable struct SSConn
    conn::TCPSocket
    cipher::Cipher
    debuff::Bytes
    enbuff::Bytes
end
SSConn(socket, cipher) = SSConn(socket, cipher, Bytes(65536), Bytes(65536))
SSConn() = SSConn(TCPSocket(), Cipher())

function getkeys(method::String, str::String)
    const md5len = 16

    password = Bytes(str)
    keylen = METHOD[method]["KEYLEN"]

    cnt = Integer(floor((keylen-1)/md5len)) + 1
    m = Bytes(cnt * md5len)
    
    buff = Array{Cuchar}(16)
    md5(buff, password)
    m[1:md5len] = buff

    for i in 2:1:cnt
        md5(buff, [buff; password])
        m[md5len * (i-1) + 1 : md5len * i] = buff
    end
    return m[1:keylen]
end

function parseCipher(config::SSConfig)
    cipher = Cipher()
    cipher.method = config.method
    cipher.add_text = Bytes(config.password)
    cipher.add_text_len = Csize_t(sizeof(config.password))
    cipher.key = getkeys(cipher.method, config.password)
    cipher.deiv = rand(UInt8, METHOD[config.method]["IVLEN"])
    cipher.eniv = rand(UInt8, METHOD[config.method]["IVLEN"])
    cipher.ctype = METHOD[config.method]["TYPE"]

    return cipher, nothing
end

function read(io::TCPSocket, buff::Bytes)
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

function read(ssConn::SSConn, buff::Bytes)
    nbytes, err = read(ssConn.conn, ssConn.debuff)
    if err != nothing
        return nothing, err
    end

    nbytes, err = decrypt(buff, ssConn.debuff, nbytes, ssConn.cipher)
    if err != nothing
        return nothing, err
    end

    return nbytes, nothing
end

function write(ssConn::SSConn, message::Bytes, nbytes::Integer)
    nbytes, err = encrypt(ssConn.enbuff, message, nbytes, ssConn.cipher)
    if err != nothing
        return err
    end

    write(ssConn.conn, ssConn.enbuff[1:nbytes])
    return nothing
end

function decrypt(buff::Bytes, ciphertext::Bytes, ciphertext_len::Integer, cipher::Cipher)
    nbytes = ccall(
        decryptor,
        Csize_t,
        (Ref{Cuchar}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Ref{Cuchar}, Cuchar),
        buff, ciphertext, ciphertext_len, cipher.add_text, cipher.add_text_len, cipher.key, cipher.deiv, cipher.ctype)

    nbytes == 0xffffffffffffffff && return nothing, ""
    return nbytes, nothing
end

function encrypt(buff::Bytes, text::Bytes, text_len::Integer, cipher::Cipher)
    nbytes = ccall(
        encryptor, 
        Csize_t, 
        (Ref{Cuchar}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Ref{Cuchar}, Cuchar), 
        buff, text, text_len, cipher.add_text, cipher.add_text_len, cipher.key, cipher.eniv, cipher.ctype)

    nbytes == 0xffffffffffffffff && return nothing, ""
    return nbytes, nothing
end


# include("Server.jl")
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

    nbytes, err = read(ssConn.conn, buff)
    if err != nothing
        close(ssConn.conn)
        return
    end

    const ivlen = METHOD[ssConn.cipher.method]["IVLEN"]
    ssConn.cipher.deiv = buff[1:ivlen]
    nbytes, err = decrypt(buff, buff[ivlen+1:nbytes], nbytes-ivlen, ssConn.cipher)
    if err != nothing
        close(ssConn.conn)
        return
    end

    client, err = connectRemote(buff)
    if err != nothing
        close(ssConn.conn)
        return
    end

    ssConn.cipher.eniv = rand(UInt8, ivlen)
    isopen(ssConn.conn) && write(ssConn.conn, ssConn.cipher.eniv)

    buff = nothing
    @async begin
        buff_in = Bytes(65536)
        while isopen(ssConn.conn) && isopen(client)
            nbytes, err = read(ssConn, buff_in)
            if err != nothing
                continue
            end

            isopen(client) && write(client, buff_in[1:nbytes])
        end

        close(client)
        close(ssConn.conn)
    end

    begin
        buff_out = Bytes(65536)
        while isopen(ssConn.conn) && isopen(client)
            nbytes, err = read(client, buff_out)
            if err != nothing
                continue
            end

            isopen(ssConn.conn) && write(ssConn, buff_out, nbytes)
        end

        close(client)
        close(ssConn.conn)
    end
end


# include("Client.jl")
function handShake(conn::TCPSocket, buff::Bytes)
    nbytes, err = read(conn, buff)
    if err != nothing
        return false
    end

    if buff[1] != 0x05
        return false
    end

    if 0x00 in buff[3:nbytes]
        isopen(conn) && begin write(conn, [0x05; 0x00]); return true; end
        return false
    else 
        isopen(conn) && write(conn, [0x05; 0xFF])
        return false
    end

    return false
end

function getRequest(conn::TCPSocket, buff::Bytes)
    nbytes, err = read(conn, buff)
    if err != nothing
        return nothing, err
    end

    if buff[2] != 0x01
        return nothing, ""
    end

    return buff[4:nbytes], nothing
end

function handleConnection(conn::TCPSocket, config::SSConfig)
	buff = Bytes(1024)
    handShake(conn, buff) || begin 
        close(conn) 
        return
    end

    req, err = getRequest(conn, buff)
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

    nbytes, err = encrypt(buff, req, Csize_t(sizeof(req)), ssConn.cipher)
    if err != nothing
        close(ssConn.conn)
        close(conn)
        return
    end

    isopen(ssConn.conn) && write(ssConn.conn, [ssConn.cipher.eniv; buff[1:nbytes]])

    nbytes, err = read(ssConn.conn, buff)
    if err != nothing
        close(ssConn.conn)
        close(conn)
        return
    end

    const ivlen = METHOD[ssConn.cipher.method]["IVLEN"]
    ssConn.cipher.deiv = buff[1:ivlen]

    if ivlen != nbytes
    end

    buff = nothing
    @async begin
        buff_in = Bytes(65536)
        while isopen(conn) && isopen(ssConn.conn)
            nbytes, err = read(conn, buff_in)
            if err != nothing
                continue
            end

            isopen(ssConn.conn) && write(ssConn, buff_in, nbytes)
        end

        close(conn)
        close(ssConn.conn)
    end

    begin
        buff_out = Bytes(65536)
        while isopen(ssConn.conn) && isopen(conn)
            nbytes, err = read(ssConn, buff_out)
            if err != nothing
                continue
            end

            isopen(conn) && write(conn, buff_out[1:nbytes])
        end

        close(conn)
        close(ssConn.conn)
    end
end


# run a Shadowsocks server or client
function run(config::SSConfig)

    config.lisPort == false && begin 
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

    isa(config.lisPort, Integer) && begin 
        server = try
            listen(getipaddr(), config.lisPort)
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
