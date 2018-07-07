using Shadowsocks
@static if VERSION < v"0.7.0-DEV.2005"
    using Base.Test
else
    using Test
end

# write your own tests here
@test 1 == 1

# @test String(Shadowsocks.getkey(Shadowsocks.AES256CFB, take!(IOBuffer("imgk1234"))))