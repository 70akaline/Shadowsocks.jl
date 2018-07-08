using Shadowsocks
@static if VERSION < v"0.7.0-DEV.2005"
    using Base.Test
else
    using Test
end

# write your own tests here
@test 1 == 1


false && begin

using Shadowsocks; run(SSServer())
using Shadowsocks; run(SSClient())
server = listen(2000)
@async conn = accept(server)
write(client, b"Julia")
String(readavailable(conn))
close(conn)

end

using Shadowsocks
@async run(SSServer())
using Shadowsocks
@async run(SSClient())

using Shadowsocks
using Base.Test
client = connect(getipaddr(), 1080)
write(client, [0x05; 0x01; 0x00])
@test readavailable(client) == [0x05; 0x00]
write(client, [0x01; 0x01; 0x00; 0x01; Shadowsocks.toIP(getipaddr()); Shadowsocks.toPort(2000)])
@test readavailable(client) == [0x05; 0x00; 0x00; 0x01; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00]
close(client)