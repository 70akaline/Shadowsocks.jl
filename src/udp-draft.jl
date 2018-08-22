
# ======udp========= need to be finished
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
