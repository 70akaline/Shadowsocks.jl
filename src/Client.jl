module Client # client

using Sockets

using ..Common: Error, SSConfig, Cipher, SSConnection, close, gensubkey, read, write, ioCopy, init_write, init_read, eof

@inline function handShake(conn::TCPSocket, buff::Array{UInt8})
    nbytes, err = read(conn, buff)
    if err != nothing
        return err
    end

    if buff[1] != 0x05
        return "Not a Socks5 Client"
    end

    if 0x00 in buff[3:nbytes]
        err = write(conn, [0x05; 0x00], 2)
        if err != nothing
            return err
        end
    else 
        write(conn, [0x05; 0xFF], 2) != nothing && return "Write Error"
        return "Not a Valid Authentication"
    end

    nbytes, err = read(conn, buff, 3)
    if err != nothing
        return err
    end

    if buff[1:3] != [0x05; 0x01; 0x00]
        return "Not a Supported CMD"
    end

    nbytes, err = read(conn, buff)
    if err != nothing
        return err
    end

    if getipaddr() isa IPv4
        err = write(conn, [0x05; 0x00; 0x00; 0x01; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00], 10)
        if err != nothing
            return err
        end
    else
        err = write(conn, [0x05; 0x00; 0x00; 0x04; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00], 22)
        if err != nothing
            return err
        end
    end

    return nbytes
end

@inline function handleConnection(conn::TCPSocket, ssConn::SSConnection) # Client
    while true
        buff = Array{UInt8}(undef, 272)
        nbytes = handShake(conn, buff)
        if !(nbytes isa Integer)
            break
        end

        err = init_write(ssConn)
        if err != nothing
            break
        end

        err = write(ssConn, buff, nbytes)
        if err != nothing
            break
        end

        @async ioCopy(conn, ssConn)

        err = init_read(ssConn)
        if err != nothing
            break
        end

        buff = nothing
        ioCopy(ssConn, conn) # First

        close(conn)
        while !eof(conn)
            sleep(1)
        end

        break
    end

    close(conn)
    close(ssConn)
end

@inline function tcpClient(config::SSConfig, cipher::Cipher)
    server = try
        listen(getipaddr() isa IPv4 ? IPv4(0) : IPv6(0), config.lisPort)
    catch err
        return
    end

    while isopen(server)
        conn = try
            accept(server)
        catch err
            break
        end

        client = try
            connect(config.host, config.port)
        catch err
            close(conn)
            continue
        end

        @async handleConnection(
            conn, 
            SSConnection(client, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Array{UInt8}(undef, cipher.taglen + 2), nothing, nothing)
        )
    end

    close(server)
end

@inline function tcpClient(configs::Array{SSConfig}, ciphers::Array{Cipher})
    server = try
        listen(getipaddr() isa IPv4 ? IPv4(0) : IPv6(0), configs[1].lisPort)
    catch err
        return
    end

    nServers = [1:length(configs)...]

    while isopen(server)
        conn = try
            accept(server)
        catch err
            break
        end

        n = rand(nServers, 1)
        cipher = ciphers[n]
        config = configs[n]

        client = try
            connect(config.host, config.port)
        catch err
            close(conn)
            continue
        end

        @async handleConnection(
            conn, 
            SSConnection(client, cipher, zeros(UInt8, cipher.ivlen), zeros(UInt8, cipher.ivlen), Array{UInt8}(undef, cipher.taglen + 2), nothing, nothing)
        )
    end

    close(server)
end

@inline function runClient(config::SSConfig)
    cipher = Cipher(config)

    # @async udpClient()
    tcpClient(config, cipher)
end

@inline function runClient(configs::Array{SSConfig})
    ciphers = Cipher.(configs)

    # @async udpclient()
    tcpClient(configs, ciphers)
end

end # module 