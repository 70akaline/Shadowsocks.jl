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
const Bytes        = Array{UInt8}
const CodeSet      = Bytes("1234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm")
const Buffer_Len   = 17408
const Package_Size = 16383
const Libcrypto    = Libdl.dlopen(joinpath(Pkg.dir("Shadowsocks"), "libs", "libcrypto"))
const METHOD       = Dict{String, Dict{String, Integer}}(
    "CHACHA20-POLY1305"       => Dict{String, Integer}("TYPE" => Cuchar(1), "KEYLEN" => 32, "TAGLEN" => 16, "IVLEN" => 8),
    "CHACHA20-POLY1305-IETF"  => Dict{String, Integer}("TYPE" => Cuchar(2), "KEYLEN" => 32, "TAGLEN" => 16, "IVLEN" => 12),
    "XCHACHA20-POLY1305-IETF" => Dict{String, Integer}("TYPE" => Cuchar(3), "KEYLEN" => 32, "TAGLEN" => 16, "IVLEN" => 24),
    "AES-256-GCM"             => Dict{String, Integer}("TYPE" => Cuchar(4), "KEYLEN" => 32, "TAGLEN" => 16, "IVLEN" => 12)
)
const CError       = 0xffffffffffffffff
const MD5Len       = 16

macro log(message)
    quote
        println(STDOUT, Dates.now(), " : ", $message)
    end
end

macro genPass(len)
    quote
    	String(rand(CodeSet, $len))
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

const MD5Func     = @dlsym("md5hash", Libcrypto)
const EncryptFunc = @dlsym("encrypt", Libcrypto)
const DecryptFunc = @dlsym("decrypt", Libcrypto)

function toPort(p)
    return hex2bytes(num2hex(UInt16(p)))
end

function toIP(ip)
    return hex2bytes(num2hex(ip.host))
end

function md5(buff, text)
    return ccall(MD5Func, Int64, (Ref{Cuchar}, Ref{Cuchar}, Csize_t), buff, Array{Cuchar}(text), Csize_t(sizeof(text)))
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
    key_len::Csize_t
    deiv::Bytes
    eniv::Bytes
    iv_len::Csize_t
    ctype::Cuchar
    isBlock::Bool
    tagLength::Union{Integer, Bool}
    aead_length_buff::Union{Bytes, Bool}
end
Cipher() = Cipher(
    "method", 
    [0x00; ], 
    Csize_t(0),
    [0x00; ],
    Csize_t(0),
    [0x00; ],
    [0x00; ],
    Csize_t(0),
    Cuchar(0),
    false,
    false,
    false)

mutable struct SSConnection
    conn::TCPSocket
    cipher::Cipher
end
SSConnection() = SSConnection(TCPSocket(), Cipher())

function getkeys(keylen::Csize_t, str::String)
    password = Bytes(str)

    cnt = Integer(floor((keylen-1)/MD5Len)) + 1
    m = Bytes(cnt * MD5Len)
    
    buff = Array{Cuchar}(MD5Len)
    md5(buff, password)
    m[1:MD5Len] = buff

    for i in 2:1:cnt
        md5(buff, [buff; password])
        m[MD5Len * (i-1) + 1 : MD5Len * i] = buff
    end
    return m[1:keylen]
end

function parseCipher(config::SSConfig)
    cipher = Cipher()
    cipher.method = config.method
    cipher.add_text = Bytes(config.password)
    cipher.add_text_len = Csize_t(sizeof(config.password))
    cipher.key_len = METHOD[config.method]["KEYLEN"]
    cipher.key = getkeys(cipher.key_len, config.password)
    cipher.iv_len = METHOD[config.method]["IVLEN"]
    cipher.deiv = rand(UInt8, cipher.iv_len)
    cipher.eniv = rand(UInt8, cipher.iv_len)
    cipher.ctype = METHOD[config.method]["TYPE"]

    if config.method in ["CHACHA20-POLY1305"; "CHACHA20-POLY1305-IETF"; 
                "XCHACHA20-POLY1305-IETF"; "AES-256-GCM"]
        cipher.isBlock = true
        cipher.tagLength = METHOD[config.method]["TAGLEN"]
        cipher.aead_length_buff = rand(UInt8, 2+cipher.tagLength)
    else 
        cipher.isBlock = false
    end

    return cipher, nothing
end

function read(io::TCPSocket, buff::Bytes)
    try
        eof(io)
    catch err
        return nothing, err
    end

    nbytes = nb_available(io)
    nbytes > Package_Size ? nbytes = Package_Size : nothing
    try 
        readbytes!(io, buff, nbytes)
    catch err
        return nothing, err
    end

    return nbytes, nothing
end

function read(io::TCPSocket, buff::Bytes, n_byte::Integer)
    try
        eof(io)
    catch err
        return nothing, err
    end

    nbytes = nothing
    while true
        nbytes = try 
            nb_available(io)
        catch err
            return nothing, err
        end

        if nbytes >= n_byte
            nbytes = n_byte
            break
        else
            sleep(0.001)
            continue
        end
    end

    try
        readbytes!(io, buff, nbytes)
    catch err
        return nothing, err
    end

    return nbytes, nothing
end

function read_aead(ssConn::SSConnection, buff::Bytes)
    nbytes, err = read(ssConn.conn, buff, 2 + ssConn.cipher.tagLength)
    if err != nothing
        return nothing, err
    end

    nbytes, err = decrypt(buff, buff, nbytes, ssConn.cipher)
    if err != nothing
        @log "decrypt error"
        return nothing, err
    end

    nbytes, err = read(ssConn.conn, buff, buff[1]*256 + buff[2] + ssConn.cipher.tagLength)
    if err != nothing
        return nothing, err
    end

    nbytes, err = decrypt(buff, buff, nbytes, ssConn.cipher)
    if err != nothing
        return nothing, err
    end

    return nbytes, nothing
end

function read_stream(ssConn::SSConnection, buff::Bytes)
    nbytes, err = read(ssConn.conn, buff)
    if err != nothing
        return nothing, err
    end

    nbytes, err = decrypt(buff, buff, nbytes, ssConn.cipher)
    if err != nothing
        return nothing, err
    end

    return nbytes, nothing
end

function write_aead(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    ssConn.cipher.aead_length_buff[1:2] = hex2bytes(num2hex(UInt16(nbytes)))
    err = write_stream(ssConn, ssConn.cipher.aead_length_buff, 2)
    if err != nothing
        return err
    end

    err = write_stream(ssConn, buff, nbytes)
    if err != nothing 
        return err
    end

    return nothing
end

function write_stream(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    nbytes, err = encrypt(buff, buff, nbytes, ssConn.cipher)
    if err != nothing
        return err
    end

    isopen(ssConn.conn) && try 
        write(ssConn.conn, buff[1:nbytes])
    catch err
        return err
    end
    return nothing
end

function decrypt(buff::Bytes, ciphertext::Bytes, ciphertext_len::Integer, cipher::Cipher)
    nbytes = ccall(
        DecryptFunc,
        Csize_t,
        (Ref{Cuchar}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Ref{Cuchar}, Cuchar),
        buff, ciphertext, ciphertext_len, cipher.add_text, cipher.add_text_len, cipher.key, cipher.deiv, cipher.ctype)

    nbytes == CError && return nothing, ""
    return nbytes, nothing
end

function encrypt(buff::Bytes, text::Bytes, text_len::Integer, cipher::Cipher)
    nbytes = ccall(
        EncryptFunc, 
        Csize_t, 
        (Ref{Cuchar}, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Csize_t, Ref{Cuchar}, Ref{Cuchar}, Cuchar), 
        buff, text, text_len, cipher.add_text, cipher.add_text_len, cipher.key, cipher.eniv, cipher.ctype)

    nbytes == CError && return nothing, ""
    return nbytes, nothing
end

function ioCopy(ssConn::SSConnection, conn::TCPSocket)
    buff = Bytes(Buffer_Len)
    ssRead = nothing
    ssConn.cipher.isBlock ? ssRead = read_aead : ssRead = read_stream
    while isopen(conn) && isopen(ssConn.conn)
        nbytes, err = ssRead(ssConn, buff)
        if err != nothing
            break
        end

        isopen(conn) && try
            write(conn, buff[1:nbytes])
        catch err
            break
        end
    end

    close(ssConn.conn)
    close(conn)
end

function ioCopy(conn::TCPSocket, ssConn::SSConnection)
    buff = Bytes(Buffer_Len)
    ssWrite = nothing
    ssConn.cipher.isBlock ? ssWrite = write_aead : ssWrite = write_stream
    while isopen(ssConn.conn) && isopen(conn)
        nbytes, err = read(conn, buff)
        if err != nothing
            break
        end

        isopen(ssConn.conn) && begin
            err = ssWrite(ssConn, buff, nbytes)
            if err != nothing 
                break
            end
        end
    end

    close(ssConn.conn)
    close(conn)
end

# include("Server.jl")
function connectRemote(payload::Bytes)
    if !(payload[1] in [0x01; 0x03; 0x04])
        return nothing, ""
    end

    host = nothing
    port = nothing

    payload[1] == 0x01 && begin
        host = IPv4(payload[2], payload[3], payload[4], payload[5])
        port = payload[6] * 256 + payload[7]
    end

    payload[1] == 0x03 && begin
        len = payload[2]
        host = String(payload[3:len+2])
        port = payload[len+3] * 256 + payload[len+4]
    end

    payload[1] == 0x04 && begin
        host = IPv6(payload[2] * 256 + payload[3], payload[4]  * 256 + payload[5],
            payload[6]  * 256 + payload[7], payload[8]  * 256 + payload[9],
            payload[10] * 256 + payload[11], payload[12] * 256 + payload[13],
            payload[14] * 256 + payload[15], payload[16] * 256 + payload[17])
        port = payload[18] * 256 + payload[19]
    end

    client = try
        connect(host, port)
    catch err
        return nothing, err
    end

    return client, nothing
end

function handleSSConnection(ssConn::SSConnection)
    buff = Bytes(1024)

    nbytes, err = read(ssConn.conn, buff)
    if err != nothing
        close(ssConn.conn)
        return
    end

    ssConn.cipher.deiv = buff[1:ssConn.cipher.iv_len]
    nbytes, err = try 
        decrypt(buff, buff[ssConn.cipher.iv_len+1:nbytes], nbytes-ssConn.cipher.iv_len, ssConn.cipher)
    catch err
        return
    end
    if err != nothing
        close(ssConn.conn)
        return
    end

    client, err = connectRemote(buff)
    if err != nothing
        close(ssConn.conn)
        return
    end

    ssConn.cipher.eniv = rand(UInt8, ssConn.cipher.iv_len)
    isopen(ssConn.conn) && write(ssConn.conn, ssConn.cipher.eniv)

    buff = nothing
    @async ioCopy(ssConn, client)
    ioCopy(client, ssConn)
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
        isopen(conn) && write(conn, [0x05; 0x00])
    else 
        isopen(conn) && write(conn, [0x05; 0xFF])
        return false
    end

    nbytes, err = read(conn, buff)
    if err != nothing
        return false
    end

    if buff[2] != 0x01
        return false
    end

    return buff[4:nbytes]
end

function handleConnection(conn::TCPSocket, cipher::Cipher, config::SSConfig)
	buff = Bytes(1024)
    req = handShake(conn, buff)
    isa(req, Bool) && begin 
        close(conn) 
        return
    end

    client = try
        connect(config.host, config.port)
    catch err
        close(conn)
        return
    end

    ipaddr = getipaddr()
    isopen(conn) && if isa(ipaddr, IPv4)
        write(conn, [0x05; 0x00; 0x00; 0x01; toIP(ipaddr); toPort(config.lisPort)])
    elseif isa(ipaddr, IPv6)
        write(conn, [0x05; 0x00; 0x00; 0x04; toIP(ipaddr); toPort(config.lisPort)])
    end
    ssConn = SSConnection(client, cipher)

    ssConn.cipher.eniv = rand(UInt8, cipher.iv_len)
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

    ssConn.cipher.deiv = buff[1:cipher.iv_len]

    if cipher.iv_len != nbytes
        nothing
    end

    buff = nothing
    @async ioCopy(conn, ssConn)
    ioCopy(ssConn, conn)
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
            @async handleSSConnection(SSConnection(conn, deepcopy(cipher)))
        end
    end

    isa(config.lisPort, Integer) && begin
        server = try
            ipaddr = getipaddr()
            if isa(ipaddr, IPv4) 
                listen(IPv4(0), config.lisPort)
            elseif isa(ipaddr, IPv6)
                listen(IPv6(0), config.lisPort)
            end
        catch err
            return
        end

        cipher, err = parseCipher(config)
        if err != nothing
            return
        end

        while isopen(server)
            conn = accept(server)
            @async handleConnection(conn, deepcopy(cipher), config)
        end
    end
end


end # module
