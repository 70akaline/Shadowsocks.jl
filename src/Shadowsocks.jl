__precompile__(false)
# 
#
#  
# A Shadowsocks implementation written in Julia
# Create by John Xiong <imgk@mail.ustc.edu.cn>
# 
# 
# 
# 
#
module Shadowsocks

include("Crypto.jl")
include("Common.jl")
include("Server.jl")
include("Client.jl")

using .Common: @terminal, SSConfig, readConfigFile, parseURI
using .Server: runServer
using .Client: runClient

import Base.run

function run(configs::Array{SSConfig}) # configure multi servers at client side
    runClient(configs)
end

function run(ch::Channel{Dict{String, Any}}) # configure multi servers at server side
    servers = Dict{String, Condition}()

    while true
        configs = take!(ch)

        key = keys(servers) # add server
        for (k, v) in configs
            if !(k in key)
                servers[k] = Condition()
                @async runServer(v, servers[k])
            end
        end

        key = keys(configs) # disable server
        for (k, ~) in servers
            if !(k in key)
                notify(servers[k])
                delete!(servers, k)
            end
        end
    end
end

end # module
