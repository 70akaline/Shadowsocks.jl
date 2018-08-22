module Server # server

using Sockets

using ..Common: Error, SSConfig, Cipher, SSConnection, close, gensubkey, read, write, ioCopy

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

@inline function gethost(buff::Array{UInt8})
    host, port = nothing, nothing
    if buff[1] == 0x01
        host = IPv4(ntoh(unsafe_load(Ptr{UInt32}(pointer(buff) + 1))))
        port = UInt16(buff[6]) << 8 | buff[7]
    elseif buff[1] == 0x03
        len = buff[2]
        host = String(unsafe_wrap(Array{UInt8}, pointer(buff) + 2, len))
        port = UInt16(buff[len+3]) << 8 | buff[len+4]
    elseif buff[1] == 0x04
        host = IPv6(ntoh(unsafe_load(Ptr{UInt128}(pointer(buff) + 1))))
        port = UInt16(buff[18]) << 8 | buff[19]
    end

    return host, port, nothing
end

@inline function connectRemote(buff::Array{UInt8})
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
        buff = Array{UInt8}(undef, 272)

        if init_read(ssConn) != nothing && break
            break
        end

        ~, err = read(ssConn, buff)
        if err != nothing
            return err
        end

        remote, err = connectRemote(buff)
        if err != nothing
            break
        end

        @async ioCopy(ssConn, remote)

        if init_write(ssConn) != nothing
            break
        end

        buff = nothing
        ioCopy(remote, ssConn)

        break
    end

    remote != nothing && close(remote)
    close(ssConn)
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
            SSConnection(conn, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Array{UInt8}(undef, cipher.taglen + 2), nothing, nothing)
        )
    end

    wait(terminate)
    close(server)
end

@inline function runServer(config::SSConfig, terminate::Condition)
    cipher = Cipher(config)

    # @async udpServer()
    tcpServer(config, cipher, terminate)
end
runServer(config::SSConfig) = runServer(config, Condition())

end # module