
module Obfs

using Dates
using Sockets

import Sockets.accept
import Base.read
import Base.write
import Base.readbytes!

using ..Crypto.Chacha20: Chacha20Encrypt, Chacha20Decrypt
using ..Crypto.HKDF: hkdf
using ..Common: ioCopy

import ..Common.read
import ..Common.write

const INFO = Array{UInt8}("obfs-tls")
const TIMEOUT = Millisecond(1000)
const ZERO = Millisecond(0)
const MaxSize = 0x5000

mutable struct TLSConfig
    host::Union{String, Sockets.IPAddr}
    port::UInt16
    key::Array{UInt8}
end

mutable struct TLSConnection
    conn::TCPSocket
    cache::IOStream
end

@inline function eof(io::TLSConnection)
    eof(io.conn)
end

@inline function isopen(io::TLSConnection)
    isopen(io.conn)
end

@inline function readbytes!(io::TLSConnection, buff::Array{UInt8}, bytes::Integer)
    readbytes!(io.conn, buff, nbytes)
end

@inline function write(io::TLSConnection, buff::Array{UInt8})
    write(io.conn, buff)
end

@inline function read(io::TLSConnection, buff::Array{UInt8})
    try
        eof(io)
    catch err
        return nothing, err
    end

    isopen(io) ? try
        readbytes(io, buff, 0x05)
    catch err
        return nothing, err
    end : return nothing, Error("Connection Closed")

    nbytes = UInt16(buff[4]) * 0x0100 + buff[5]

    isopen(io) ? try 
        readbytes!(io, buff, nbytes)
    catch err
        return nothing, err
    end : return nothing, Error("Connection Closed")

    return nbytes, nothing
end

@inline function read(io::TLSConnection, buff::Array{UInt8}, nbytes::Integer)
    while true
        if nbytes <= bytesavailable(io.cache)
            readbytes!(io.cache, buff, nbytes)
            break
        end

        nread, err = read(io, buff)
        if err != nothing
            return nothing, err
        end

        write(io.cache, unsafe_wrap(Array{UInt8}, pointer(buff), nread))
    end

    return nbytes, nothing
end

@inline function write(io::TLSConnection, buff::Array{UInt8}, nbytes::Integer)
    isopen(io) ? try 
        write(io, [[0x17, 0x03, 0x03, ]; UInt8[nbytes >> 8, nbytes & 0xff, ]])
        write(io, unsafe_wrap(Array{UInt8}, pointer(buff), nbytes)) 
    catch err 
        return err 
    end : return Error("Connection Closed")

    return nothing
end

mutable struct RandomSet
    isready::Bool
    ready::Condition
    set::Set{Array{UInt8}}
end

struct Error <: Exception
    msg::AbstractString
end

function add(random::Array{UInt8}, set::RandomSet)
    if isready
        isready = false
    else
        wait(set.ready)
        isready = false
    end

    union!(set, [random, ])

    isready = true
    notify(set.ready)
end

function clear(set::RandomSet)
    if isready
        isready = false
    else
        wait(set.ready)
        isready = false
    end

    set.set = Set{Array{UInt8}}()

    isready = true
    notify(set.ready)
end

function hasRandom(random::Array{UInt8}, set::RandomSet)::Bool
    if isready
        isready = false
    else
        wait(set.ready)
        isready = false
    end

    x = random in set.set

    isready = true
    notify(set.ready)

    x
end

function genRandom(config::TLSConfig)::Array{UInt8}
    random = Array{UInt8}(undef, 32)
    random[24:32] = rand(UInt8, 9)
    kv, err = hkdf("SHA2-256", random[24:32], config.key, INFO, 44)
    Chacha20Encrypt(random, kv[1:32], kv[33:44], Array{UInt8}(string(Dates.now())))

    random
end

function checkRandom(random::Array{UInt8}, config::TLSConfig)::Bool
    x = Array{UInt8}(undef, 23)
    kv, err = hkdf("SHA2-256", random[24:32], config.key, INFO, 44)
    Chacha20Decrypt(x, kv[1:32], kv[33:44], random[1:23])

    now = try 
        Dates.now() - parse(Dates.DateTime, String(x))
    catch err
        return false
    end

    if ZERO < now < TIMEOUT
        true
    else
        false
    end
end

function parseClientHello(buff::Array{UInt8})::Tuple{Union{Array{UInt8}, Nothing}, Union{Array{UInt8}, Nothing}, Union{Exception, Nothing}}
    while true 
        pointer = 6;
        if buff[pointer] != 0x01
            break
        end

        pointer += 6;
        random = buff[pointer:pointer+32]

        pointer += 33;
        sessionId = buff[pointer:pointer+32]
        
        return random, sessionId, nothing
    end

    return nothing, nothing, Error("Not a Valid Client Hello Message")
end

function composeExtension()
    [0x00, ]
end

function composeClientHello(config::TLSConfig)::Array{UInt8}
    [[0x16, ]; [0x03, 0x03, ]; [0x00, 0x00];
        [
            [0x01, ];
            [0x00, 0x01, 0xfc];
            [0x03, 0x03];
            genRandom(config);
            [0x20, ];
            rand(UInt8, 0x20);
            [0x00, 0x1c];
            [0x2a, 0x2a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, ];
            [0x01, ];
            [0x00, ];
            [0x01, 0x97, ];
            composeExtension()
        ]
    ]
end

function composeServerHello(sessionId::Array{UInt8})::Array{UInt8}
    [[0x16, ]; [0x03, 0x03, ]; []; 
        [
            [0x02, ]; 
            [0x00, 0x00, 0x4d, ];
            [0x03, 0x03];
            rand(UInt8, 0x20);
            [0x20, ];
            sessionId;
            [0xc0, 0x30, ];
            [0x00, ];
            [0x00, 0x05, ];
            [0xff, 0x01, 0x00, 0x01, 0x00, ]
        ]
    ]
end

function composeChangeCipher()
    [[0x14, ]; [0x03, 0x03, ]; [0x00, 0x01, ]; [0x01, ]]
end

function composeFinished()
    [[0x16, ]; [0x03, 0x03, ]; [0x00, 0x40, ]; rand(UInt8, 0x28); Array{UInt8}(undef, 0x18)]
end

function accept(server::Sockets.TCPServer, config::TLSConfig)::TCPSocket
    if @isdefined set

    else
        global set = RandomSet(true, Condition(), Set{Array{UInt8}}())
        @async while true
            sleep(3600)
            clear(set)
        end
    end

    buff = Array{UInt8}(undef, 1024)

    while true
        conn = try 
            accept(server)
        catch err 
            throw(err)
        end

        nbytes, err = read(conn, buff)
        if err != nothing
            close(conn)
            continue
        end

        random, sessionId, err = parseClientHello(buff)
        if err != nothing
            close(conn)
            continue
        end

        if checkRandom(random, config) && !hasRandom(random, set)
            add(random, set)
            read(conn, buff, 75)
            return conn
        else
            fake = try 
                connect(config.host, config.port)
            catch err 
            end

            err = write(fake, buff, nbytes)
            if err != nothing
            end

            @async ioCopy(conn, fake)
            @async ioCopy(fake, conn)
        end
    end
end

end # module


if false

using Shadowsocks
using Sockets

config = Shadowsocks.Obfs.TLSConfig(IPv4(13,35,15,164), 0x01bb, Array{UInt8}("julia"))
server = listen(2000)

Shadowsocks.Obfs.accept(server, config)

end
