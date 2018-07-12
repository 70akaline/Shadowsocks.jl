using Shadowsocks

@static if VERSION < v"0.7.0-DEV.2005"
    using Base.Test
else
    using Test
end

# write your own tests here
@test 1 == 1

# basic funtion
@test [0x00; 0x50] == Shadowsocks.@ToPort 80
@test [0x00; 0x50] == Shadowsocks.toPort(80)
@test [0xc0; 0xa8; 0x01; 0x01] == Shadowsocks.@ToIP IPv4(192,168,1,1)
@test [0xc0; 0xa8; 0x01; 0x01] == Shadowsocks.toIP(IPv4(192,168,1,1))

buff = Array{UInt8}(16)
Shadowsocks.md5(buff, "Julia")
@test [0x23; 0x44; 0x52; 0x1e; 0x38; 0x9d; 0x68; 0x97; 0xae; 0x7a; 0xf9; 0xab; 0xf1; 0x6e; 0x7c; 0xcc] == buff
# Shadowsocks.@Md5(buff, "Julia")
# @test [0x23; 0x44; 0x52; 0x1e; 0x38; 0x9d; 0x68; 0x97; 0xae; 0x7a; 0xf9; 0xab; 0xf1; 0x6e; 0x7c; 0xcc] == buff

key = Shadowsocks.getkeys("CHACHA20-POLY1305", "Julia") 
@test sizeof(key) == 32
@test key == [0x23; 0x44; 0x52; 0x1e; 0x38; 0x9d; 0x68; 0x97; 0xae; 0x7a; 0xf9; 0xab; 0xf1; 0x6e; 0x7c; 0xcc; 0x24; 0x70; 0xab; 0x47; 0x41; 0xa3; 0x14; 0x7a; 0x17; 0x06; 0xd1; 0xf4; 0xfe; 0x28; 0xe8; 0x27]

# read(io::TCPSocket, buff)
server = listen(2000)
conn = nothing
buff = Array{UInt8}(1024)
@async begin
	conn = accept(server)
	while isopen(conn)
		read(conn, buff)
		close(conn)
	end
end

client = connect(2000)
write(client, Array{UInt8}("Julia"))
@test String(buff[1:5]) == "Julia"
close(client)

cipher, err = Shadowsocks.parseCipher(SSServer())
cipher.eniv = cipher.deiv

# decrypt, encrypt
text = Array{UInt8}("Julia")
nbytes, err = Shadowsocks.encrypt(buff, text, sizeof(text), cipher)
nbytes, err = Shadowsocks.decrypt(buff, buff[1:nbytes], nbytes, cipher)
@test text == buff[1:nbytes]

# ssConn read
@async begin
	conn = accept(server)
	ssConn = Shadowsocks.SSConn(conn, cipher)
	nbytes, err = read(ssConn, buff)
	close(conn)
end
client = connect(2000)
nbytes, err = Shadowsocks.encrypt(buff, text, sizeof(text), cipher)
write(client, buff[1:nbytes])
@test text == buff[1:5]
close(client)


# ssConn write
@async begin
    conn = accept(server)
	ssConn = Shadowsocks.SSConn(conn, cipher)
	err = write(ssConn, text, 5)
	close(conn)
end
client = connect(2000)
nbytes, err = read(client, buff)
nbytes, err = Shadowsocks.decrypt(buff, buff[1:nbytes], nbytes, cipher)
@test text == buff[1:nbytes]
close(client)

# test ssclient
server = listen(2000)
@async run(SSServer())
@async run(SSClient())

client = connect(getipaddr(), 1080)
write(client, [0x05; 0x01; 0x00])
@test readavailable(client) == [0x05; 0x00]
write(client, [0x01; 0x01; 0x00; 0x01; Shadowsocks.toIP(getipaddr()); Shadowsocks.toPort(2000)])
@test readavailable(client) == [0x05; 0x00; 0x00; 0x01; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00]
close(client)
