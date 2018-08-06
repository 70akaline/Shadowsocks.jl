#!/usr/bin/env julia

using Shadowsocks
using Sockets
using ArgParse

function main(args)
    s = ArgParseSettings(description = "This is a julia implementation of shadowsocks",
        commands_are_required = false,
        version = "0.1",
        add_version = false)

    @add_arg_table s begin
        "--server", "-s"
            help = "shadowsocks sever"
        "--port", "-p"
            help = "shadowsocks server port"
            arg_type = Int
        "--listen", "-l"
            help = "shadowsocks listen port"
            arg_type = Int
        "--method", "-m"
            help = "encryption method\nCHACHA20-POLY1305-IETF, XCHACHA20-POLY1305-IETF, AES-256-GCM"
        "--password", "-k"
            help = "access password, [a-zA-Z_0-9]+"
        "--uri", "-c"
            help = "ss://chacha20-poly1305-ietf:imgk0000@127.0.0.1:8388\nor ss://chacha20-poly1305-ietf:imgk0000@:8388"
    end

    config = nothing

    if args == String[]
        main(String["--help"])
    else
        parsed_args = parse_args(args, s)
        if haskey(parsed_args, "uri")
            config, err = Shadowsocks.parseURI(parsed_args["uri"])
            if err != nothing
                main(String["--help"])
            end
        else
            ip = parse(Sockets.IPAddr, parsed_args["server"])
            if haskey(parsed_args, "listen")
                config = SSClient(
                    ip, 
                    parsed_args["port"], 
                    parsed_args["listen"], 
                    uppercase(parsed_args["method"]), 
                    parsed_args["password"]
                )
            else
                config = SSServer(
                    ip, 
                    parsed_args["port"], 
                    uppercase(parsed_args["method"]), 
                    parsed_args["password"]
                )
            end
        end
    end

    if config.lisPort == nothing
        Shadowsocks.@terminal("running shadowsocks server")
    else
        Shadowsocks.@terminal("running shadowsocks client")
    end

    run(config)
end

main(ARGS)
