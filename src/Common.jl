module Common # Common

using Sockets
using Dates
using JSON

using ..Crypto

import Base.isopen
import Base.close
import Base.read
import Base.write

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
    ivDecrypt::Union{Array{UInt8}, Nothing}
    ivEncrypt::Union{Array{UInt8}, Nothing}
    tagCache::Union{Array{UInt8}, Nothing}
    keyDecrypt::Union{Array{UInt8}, Nothing}
    keyEncrypt::Union{Array{UInt8}, Nothing}
end

@inline function close(ssConn::SSConnection)
    return close(ssConn.conn)
end

@inline function isopen(ssConn::SSConnection)
    return isopen(ssConn.conn)
end

@inline function increase(iv::Array{UInt8})
    for i in 1:length(iv)
        iv[i] += 0x01
        if iv[i] != 0x00
            break
        end
    end
end

@inline function init_read(ssConn::SSConnection) # Server
    saltlen = max(16, ssConn.cipher.keylen)

    salt = Array{UInt8}(undef, saltlen)
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

struct Error <: Exception
    msg::AbstractString
end

@inline function genkey(keylen::UInt64, password::String)
    cnt = fld(keylen, MD5Len)
    left = keylen % MD5Len
    tmp = Array{UInt8}(undef, cnt * MD5Len + left)
    
    len = sizeof(password)
    buff = Array{UInt8}(undef, MD5Len + len)
    pass = unsafe_wrap(Array{UInt8}, pointer(password), len)
    buff[MD5Len + 1 : end] = pass
    buff[1 : MD5Len] = Crypto.MD5.md5(pass)
    md5hash = unsafe_wrap(Array{UInt8}, pointer(buff), MD5Len)
    tmp[1 : MD5Len] = md5hash

    for i in 2 : cnt
        buff[1 : MD5Len] = Crypto.MD5.md5(buff)
        tmp[MD5Len * (i-1) + 1 : MD5Len * i] = md5hash
    end

    left != 0 && begin tmp[MD5Len * cnt + 1 : MD5Len * cnt + left] = Crypto.MD5.md5(buff)[1 : left] end

    return tmp
end

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
        return nothing, Error("Generate Sub Key Error")
    end

    return subkey, nothing
end

@inline function read(io::TCPSocket, buff::Bytes)
    try
        eof(io)
    catch err
        return nothing, err
    end

    nbytes = min(MaxSize, bytesavailable(io))
    isopen(io) ? try 
        readbytes!(io, buff, nbytes)
    catch err
        return nothing, err
    end : return nothing, Error("Connection Closed")

    return nbytes, nothing
end

@inline function read(io::TCPSocket, buff::Bytes, nbytes::Integer)
    try
        eof(io)
    catch err
        return nothing, err
    end

    isopen(io) ? try 
        readbytes!(io, buff, nbytes)
    catch err 
        return nothing, err
    end : return nothing, Error("Connection Closed")

    return nbytes, nothing
end

@inline function write(io::TCPSocket, buff::Bytes, nbytes::Integer)
    isopen(io) ? try 
        write(io, unsafe_wrap(Array{UInt8}, pointer(buff), nbytes)) 
    catch err 
        return err 
    end : return Error("Connection Closed")

    return nothing
end

@inline function read(ssConn::SSConnection, buff::Bytes)
    nbytes, err = read_stream(ssConn, buff, 2 + ssConn.cipher.taglen)
    if err != nothing
        return nothing, err
    end
    increase(ssConn.ivDecrypt)

    nbytes, err = read_stream(ssConn, buff, UInt16(buff[1]) * 256 + buff[2] + ssConn.cipher.taglen)
    if err != nothing
        return nothing, err
    end
    increase(ssConn.ivDecrypt)

    return nbytes, nothing
end

@inline function write(ssConn::SSConnection, buff::Bytes, nbytes::Integer)
    ssConn.tagCache[1:2] = [UInt8(nbytes >> 8); UInt8(nbytes & 0xff)]
    err = write_stream(ssConn, ssConn.tagCache, 2)
    if err != nothing
        return err
    end
    increase(ssConn.ivEncrypt)

    err = write_stream(ssConn, buff, nbytes)
    if err != nothing 
        return err
    end
    increase(ssConn.ivEncrypt)

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

function ioCopy(from::SSConnection, to::TCPSocket)
    buff = Array{UInt8}(undef, MaxSize + from.cipher.taglen)
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

function ioCopy(from::TCPSocket, to::SSConnection)
    buff = Array{UInt8}(undef, MaxSize + to.cipher.taglen)
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

end # module