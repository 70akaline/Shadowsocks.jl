
module Obfs

module tls

using Dates
using Sockets

import Sockets: accept

using ....Crypto.Chacha20: Chacha20Encrypt, Chacha20Decrypt
using ....Crypto.HKDF: hkdf
using ....Common: ioCopy, read, write

const INFO = Array{UInt8}("obfs-tls")
const TIMEOUT = Millisecond(1000)
const ZERO = Millisecond(0)

mutable struct TLSConfig
    host::String
    port::UInt16
    key::Array{UInt8}
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
    kv = hkdf("SHA2-256", random[24:32], config.key, INFO, 44)
    Chacha20Encrypt(random, kv[1:32], kv[33:44], Array{UInt8}(string(Dates.now())))
    random
end

function checkRandom(random::Array{UInt8}, config::TLSConfig)::Bool
    x = Array{UInt8}(undef, 23)
    kv = hkdf("SHA2-256", random[24:32], config.key, INFO, 44)
    Chacha20Decrypt(x, kv[1:32], kv[33:44], random[1:23])
    if ZERO < Dates.now() - parse(Dates.Time, String(x)) < TIMEOUT
        true
    else
        false
    end
end

function parseRandom(buff::Array{UInt8})::Tuple{Union{Array{UInt8}, Nothing}, Union{Exception, Nothing}}
end

function composeClientHello()
end

function composeClientRespond()
end

function composeServerRespond(buff::Array{UInt8})
end

function accept(server::TCPSocket, config::TLSConfig)::TCPSocket
    if @isdefined set
        nothing
    else
        global set = RandomSet(true, Condition(), Set{Array{UInt8}}())
        @async while true
            sleep(3600)
            clear(set)
        end
    end
    buff = Array{UInt8}(512)

    conn = try 
        accept(server)
    catch err 
        throw(err)
    end

    nbytes, err = read(conn, buff, 512)
    random, err = parseRandom(buff)
    if err != nothing
    end

    if checkRandom(random, config) && !hasRandom(random, set)
        read(conn, buff, 512)
        conn
    else
        fake = try 
            connect(set.host, set.port)
        catch err 
        end

        err = write(fake, buff, nbytes)
        if err != nothing
        end

        @async ioCopy(conn, fake)
        @async ioCopy(fake, conn)
    end
end

end # module

end # module
