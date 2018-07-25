#!/usr/bin/env julia

using Shadowsocks
using ArgParse

function main(args)
    s = ArgParseSettings(description = "This is a julia implementation of ss-local",
        commands_are_required = false,
        version = "0.1",
        add_version = false)

    @add_arg_table s begin
        "--server", "-s"
            help = "shadowsocks sever"
            default = "0.0.0.0"
            required = true
        "--port", "-p"
            help = "shadowsocks server port"
            arg_type = Int
            default = 8388
            required = true
        "--listen", "-l"
            help = "shadowsocks listen port"
            arg_type = Int
            default = 1080
            required = true
        "--method", "-m"
            help = "encryption method"
            default = "CHACHA20-POLY1305-IETF"
            required = true
        "--password", "-k"
            help = "access password"
            default = "imgk0000"
            required = true
    end

    parsed_args = parse_args(args, s)
    ip, err = parseip(parsed_args["server"])
    err != nothing && main(String["--help"])
    Shadowsocks.@log("running shadowsocks client")
    run(SSClient(
        ip, 
        parsed_args["port"], 
        parsed_args["listen"], 
        uppercase(parsed_args["method"]), 
        parsed_args["password"]
        )
    )
end

function parseip(ip::String)
    t = split(ip, ".")
    length(t) != 4 && return nothing, "Not a Valid IP Address"
    return IPv4(
        parse(Int, t[1]),
        parse(Int, t[2]),
        parse(Int, t[3]),
        parse(Int, t[4])
    ), nothing
end

main(ARGS)
