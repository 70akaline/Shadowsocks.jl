#!/usr/bin/env julia

using Shadowsocks
using Sockets
using ArgParse
using FileWatching

function main(args)
    s = ArgParseSettings(description = "This is a julia implementation of shadowsocks",
        commands_are_required = false,
        version = "0.0.2",
        add_version = true)

    @add_arg_table s begin
        "--server", "-s"
            help = "shadowsocks server"
        "--port", "-p"
            help = "shadowsocks server port"
            arg_type = Int
        "--listen", "-l"
            help = "shadowsocks listen port"
            arg_type = Int
        "--method", "-m"
            help = "encryption method\nchacha20-poly1305-ietf, xchacha20-poly1305-ietf"
        "--password", "-k"
            help = "access password, like Pass1234"
        "--uri", "-c"
            help = "ss://chacha20-poly1305-ietf:imgk0000@127.0.0.1:8388\nor ss://chacha20-poly1305-ietf:imgk0000@:8388"
        "--config-file", "-f"
            help = "use config file"
    end

    config = nothing

    if args == String[]
        main(String["--help"])
    else
        parsed_args = parse_args(args, s)
        if parsed_args["config-file"] != nothing
            config = Base.Filesystem.abspath(parsed_args["config-file"])
        elseif parsed_args["uri"] != nothing
            config, err = Shadowsocks.parseURI(parsed_args["uri"])
            if err != nothing
                main(String["--help"])
            end
        else
            if haskey(parsed_args, "listen")
                config = Shadowsocks.SSClient(
                    parse(Sockets.IPAddr, parsed_args["server"]), 
                    parsed_args["port"], 
                    parsed_args["listen"], 
                    uppercase(parsed_args["method"]), 
                    parsed_args["password"]
                )
            else
                config = Shadowsocks.SSServer(
                    parse(Sockets.IPAddr, parsed_args["server"]), 
                    parsed_args["port"], 
                    uppercase(parsed_args["method"]), 
                    parsed_args["password"]
                )
            end
        end
    end

    if config isa String
        if (local configs = Shadowsocks.readConfigFile(config); configs isa Array{Shadowsocks.SSConfig})
            Shadowsocks.@terminal("running shadowsocks client")
            Shadowsocks.run(configs)
        elseif configs isa Dict{String, Any}
            ch = Channel{Dict{String, Any}}(1)
            put!(ch, configs)

            @async while true # watch config file
                watch_file(config, -1)
                put!(ch, Shadowsocks.readConfigFile(config))
            end

            Shadowsocks.@terminal("running shadowsocks server")
            Shadowsocks.@terminal("watching config file - $config")
            Shadowsocks.run(ch)
        end
    elseif config isa Shadowsocks.SSConfig && config.lisPort == nothing
        Shadowsocks.@terminal("running shadowsocks server")
        Shadowsocks.runServer(config)
    elseif config isa Shadowsocks.SSConfig && config.lisPort != nothing
        Shadowsocks.@terminal("running shadowsocks client")
        Shadowsocks.runClient(config)
    end

    main(String["--help"])
end

main(ARGS)
# main(["-c", "ss://chacha20-poly1305-ietf:imgk0000@:8388"])
# main(["-c", "ss://chacha20-poly1305-ietf:imgk0000@0.0.0.0:8388"])
