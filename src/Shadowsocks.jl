__precompile__(false)

module Shadowsocks

# package code goes here

export SSServer, SSClient, run

using AES # https://github.com/faf0/AES.jl.git
using LegacyStrings # https://github.com/JuliaStrings/LegacyStrings.jl.git

import Base.run
import Base.read
import Base.write

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

dir = Pkg.dir("Shadowsocks")
libcrypto = Libdl.dlopen(joinpath(dir, "libs", "libcrypto"))
md5hash = @dlsym("md5hash", libcrypto)
encryptor = @dlsym("encrypt", libcrypto)
decryptor = @dlsym("decrypt", libcrypto)

macro Md5(buff, text)
    return :(ccall(md5hash, Int64, (Ref{Cuchar}, Ref{Cuchar}, Csize_t), $buff, $text, Csize_t(sizeof($text))))
end

function md5(buff, text)
    return ccall(md5hash, Int64, (Ref{Cuchar}, Ref{Cuchar}, Csize_t), buff, Array{Cuchar}(text), Csize_t(sizeof(text)))
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
    deiv::Bytes
    eniv::Bytes
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
    cipher.key = getkeys(cipher.method, config.password)
    cipher.deiv = rand(UInt8, METHOD[config.method]["IVLEN"])
    cipher.eniv = rand(UInt8, METHOD[config.method]["IVLEN"])

    config.method == "AES-256-CFB" && begin
        cipher.encrypt = (buff::Bytes, key::Bytes, iv::Bytes) -> AESCFB(buff, key, iv, true)
        cipher.decrypt = (buff::Bytes, key::Bytes, iv::Bytes) -> AESCFB(buff, key, iv, false)
        return cipher, nothing
    end
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
    nbytes, err = read(ssConn.conn, buff)
    if err != nothing
        return nothing, err
    end

    data, err = decrypt(buff[1:nbytes], ssConn.cipher)
    if err != nothing
        return nothing, err
    end

    return data, nothing
end

function write(ssConn::SSConn, buff::Bytes)
    data, err = encrypt(buff, ssConn.cipher)
    if err != nothing
        return err
    end

    write(ssConn.conn, data)
    return nothing
end

function decrypt(buff::Bytes, cipher::Cipher)
    if cipher.method == "AES-256-CFB"
        data = try 
            cipher.decrypt(buff, cipher.key, cipher.deiv)
        catch err
            return nothing, err
        end
    end

    return data, nothing
end

function encrypt(buff::Bytes, cipher::Cipher)
    if cipher.method == "AES-256-CFB"
        data = try 
            cipher.encrypt(buff, cipher.key, cipher.eniv)
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

    nbytes, err = read(ssConn.conn, buff)
    if err != nothing
        close(ssConn.conn)
        return
    end

    const ivlen = METHOD[ssConn.cipher.method]["IVLEN"]
    ssConn.cipher.deiv = buff[1:ivlen]
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

    ssConn.cipher.eniv = rand(UInt8, ivlen)
    isopen(ssConn.conn) && write(ssConn.conn, ssConn.cipher.eniv)

    buff = nothing
    @async begin
        buff_in = Bytes(65536)
        while isopen(ssConn.conn) && isopen(client)
            data, err = read(ssConn, buff_in)
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
            nbytes, err = read(client, buff_out)
            if err != nothing
                continue
            end

            isopen(ssConn.conn) && write(ssConn, buff_out[1:nbytes])
        end

        close(client)
        close(ssConn.conn)
    end
end

function handShake(conn::TCPSocket)
    buff = Bytes(1024)
    nbytes, err = read(conn, buff)
    if err != nothing
        return false
    end

    if buff[1] != 0x05
        return false
    end

    if 0x00 in buff[3:end]
        isopen(conn) && begin write(conn, [0x05; 0x00]); return true; end
        return false
    else 
        isopen(conn) && write(conn, [0x05; 0xFF])
        return false
    end

    return false
end

function getRequest(conn::TCPSocket)
    buff = Bytes(1024)
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
"""
客户端连到服务器后，然后就发送请求来协商版本和认证方法：
**客户端** 请求第一步
+----+----------+----------+ 
| VER|NMETHODS  | METHODS  |
+----+----------+----------+ 
| 1  |    1     | 1 - 255  |
+----+----------+----------+ 
VER 表示版本号:sock5 为 X'05'
NMETHODS（方法选择）中包含在METHODS（方法）中出现的方法标识的数据（用字节表示）

目前定义的METHOD有以下几种:
X'00'  无需认证
X'01'  通用安全服务应用程序(GSSAPI)
X'02'  用户名/密码 auth (USERNAME/PASSWORD)
X'03'- X'7F' IANA 分配(IANA ASSIGNED) 
X'80'- X'FE' 私人方法保留(RESERVED FOR PRIVATE METHODS) 
X'FF'  无可接受方法(NO ACCEPTABLE METHODS) 

**服务器** 响应第一步
服务器从客户端发来的消息中选择一种方法作为返回
服务器从METHODS给出的方法中选出一种，发送一个METHOD（方法）选择报文：
+----+--------+ 
|VER | METHOD | 
+----+--------+ 
| 1　| 　1　 　| 
+----+--------+ 

"""
    handShake(conn) || begin 
        close(conn) 
        return
    end
"""
**第二步**
一旦方法选择子商议结束，客户机就发送请求细节。如果商议方法包括了完整性检查的目的或机密性封装
，则请求必然被封在方法选择的封装中。 

SOCKS请求如下表所示:
+----+-----+-------+------+----------+----------+ 
| VER| CMD | RSV   | ATYP |  DST.ADDR|  DST.PORT|
+----+-----+-------+------+----------+----------+ 
| 1  | 1   | X'00' | 1    | variable |      2   |
+----+-----+-------+------+----------+----------+ 

各个字段含义如下:
VER  版本号X'05'
CMD：  
     1. CONNECT X'01'
     2. BIND    X'02'
     3. UDP ASSOCIATE X'03'
RSV  保留字段
ATYP IP类型 
     1.IPV4 X'01'
     2.DOMAINNAME X'03'
     3.IPV6 X'04'
DST.ADDR 目标地址 
     1.如果是IPv4地址，这里是big-endian序的4字节数据
     2.如果是FQDN，比如"www.nsfocus.net"，这里将是:
       0F 77 77 77 2E 6E 73 66 6F 63 75 73 2E 6E 65 74
       注意，没有结尾的NUL字符，非ASCIZ串，第一字节是长度域
     3.如果是IPv6地址，这里是16字节数据。
DST.PORT 目标端口（按网络次序排列） 

**sock5响应如下:**
OCKS Server评估来自SOCKS Client的转发请求并发送响应报文:
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
VER  版本号X'05'
REP  
     1. 0x00        成功
     2. 0x01        一般性失败
     3. 0x02        规则不允许转发
     4. 0x03        网络不可达
     5. 0x04        主机不可达
     6. 0x05        连接拒绝
     7. 0x06        TTL超时
     8. 0x07        不支持请求包中的CMD
     9. 0x08        不支持请求包中的ATYP
     10. 0x09-0xFF   unassigned
RSV         保留字段，必须为0x00
ATYP        用于指明BND.ADDR域的类型
BND.ADDR    CMD相关的地址信息，不要为BND所迷惑
BND.PORT    CMD相关的端口信息，big-endian序的2字节数据
"""
    req, err = getRequest(conn)
    if err != nothing 
        close(conn)
        return
    end
"""
"""
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

    isopen(ssConn.conn) && write(ssConn.conn, [ssConn.cipher.eniv; data])

    buff = Bytes(1024)
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

            isopen(ssConn.conn) && write(ssConn, buff_in[1:nbytes])
        end

        close(conn)
        close(ssConn.conn)
    end

    begin
        buff_out = Bytes(65536)
        while isopen(ssConn.conn) && isopen(conn)
            data, err = read(ssConn, buff_out)
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
