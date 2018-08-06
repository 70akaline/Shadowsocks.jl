
module MD5

# MD5 Function, Copy from JanMD5.jl

mutable struct MD5_CTX
    state::Vector{UInt32}
    bytecount::UInt64
    buffer::Vector{UInt8}
    M::Vector{UInt32}
end

function md5(data::Array{UInt8,1})
    ctx = MD5_CTX()
    update!(ctx, data)
    return digest!(ctx)
end

md5(str::AbstractString) = md5(convert(Array{UInt8,1}, str))
md5(io::IO) = md5(read(io))

digestlen(::Type{MD5_CTX}) = 16
state_type(::Type{MD5_CTX}) = UInt32
blocklen(::Type{MD5_CTX}) = UInt64(64)

const MD5_initial_hash_value = UInt32[
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,]

const S_MD5 = UInt32[
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,]

@assert length(S_MD5) == 64
@assert S_MD5[33] == 4
@assert last(S_MD5) == 21

MD5_CTX() = MD5_CTX(copy(MD5_initial_hash_value), 0, zeros(UInt8, blocklen(MD5_CTX)),
                    zeros(UInt32,16))

import Base.copy
copy(ctx::MD5_CTX) = MD5_CTX(copy(ctx.state), ctx.bytecount, copy(ctx.buffer))

## =============
# stuff copy pasted from Sha.jl

# Common update and digest functions which work across SHA1 and SHA2

# update! takes in variable-length data, buffering it into blocklen()-sized pieces,
# calling transform!() when necessary to update the internal hash state.
function update!(context::MD5_CTX,data)
    T = typeof(context)
    # We need to do all our arithmetic in the proper bitwidth
    UIntXXX = typeof(context.bytecount)

    # Process as many complete blocks as possible
    len = convert(UIntXXX, length(data))
    data_idx = convert(UIntXXX, 0)
    usedspace = context.bytecount % blocklen(T)
    while len - data_idx + usedspace >= blocklen(T)
        # Fill up as much of the buffer as we can with the data given us
        for i in 1:(blocklen(T) - usedspace)
            context.buffer[usedspace + i] = data[data_idx + i]
        end

        transform!(context)
        context.bytecount += blocklen(T) - usedspace
        data_idx += blocklen(T) - usedspace
        usedspace = convert(UIntXXX, 0)
    end

    # There is less than a complete block left, but we need to save the leftovers into context.buffer:
    if len > data_idx
        for i = 1:(len - data_idx)
            context.buffer[usedspace + i] = data[data_idx + i]
        end
        context.bytecount += len - data_idx
    end
end

lrot(b,x,width) = ((x << b) | (x >> (width - b)))
## =============

const K_MD5 = UInt32[floor(UInt32, 2^32 * abs(sin(i))) for i in 1:64]
@assert last(K_MD5) == 0xeb86d391
@assert K_MD5[29] == 0xa9e3e905

# transform!(ctx::MD5_CTX) = transform_baseline!(ctx)
transform!(ctx::MD5_CTX) = transform_unrolled!(ctx)

@generated function transform_unrolled!(context::MD5_CTX)
    ret = quote
        pbuf = Ptr{UInt32}(pointer(context.buffer))
        M = context.M
    end
    for i in 1:16
        ex = :(M[$i] = unsafe_load(pbuf,$i))
        push!(ret.args, ex)
    end
    ex  = quote
        A = context.state[1]
        B = context.state[2]
        C = context.state[3]
        D = context.state[4]
    end
    push!(ret.args, ex)
    for i in 0:63
        if 0 ≤ i ≤ 15
            ex = :(F = (B & C) | ((~B) & D))
            g = i
        elseif 16 ≤ i ≤ 31
            ex = :(F = (D & B) | ((~D) & C))
            g = 5i + 1
        elseif 32 ≤ i ≤ 47
            ex = :(F = B ⊻ C ⊻ D)
            g = 3i + 5
        elseif 48 ≤ i ≤ 63
            ex = :(F = C ⊻ (B | (~D)))
            g = 7i
        end
        push!(ret.args, ex)
        g = (g % 16) + 1
        ex = quote
            temp = D
            D = C
            C = B
            inner = A + F + $(K_MD5[i+1]) + M[$g]
            rot_inner = lrot($(S_MD5[i+1]), inner, 32)
            B = B + rot_inner
            A = temp
        end
        push!(ret.args, ex)
    end

    ex = quote
        context.state[1] += A
        context.state[2] += B
        context.state[3] += C
        context.state[4] += D
    end
    push!(ret.args, ex)
    quote
        @inbounds $ret
    end
end

function transform_baseline!(context::MD5_CTX)
    pbuf = Ptr{UInt32}(pointer(context.buffer))
    for i in 1:16
        context.M[i] = unsafe_load(pbuf,i)
    end
    A = context.state[1]
    B = context.state[2]
    C = context.state[3]
    D = context.state[4]
    for i in 0:63
        if 0 ≤ i ≤ 15
            F = (B & C) | ((~B) & D)
            g = i
        elseif 16 ≤ i ≤ 31
            F = (D & B) | ((~D) & C)
            g = (5i + 1)
        elseif 32 ≤ i ≤ 47
            F = xor(B,C,D)
            g = (3i + 5)
        elseif 48 ≤ i ≤ 63
            F = C ⊻ (B | (~D))
            g = (7i)
        end
        g = g % 16

        temp = D
        D = C
        C = B
        inner = A + F + K_MD5[i+1] + context.M[g+1]
        rot_inner = lrot(S_MD5[i+1], inner, 32)
        B = B + rot_inner
        A = temp
    end

    context.state[1] += A
    context.state[2] += B
    context.state[3] += C
    context.state[4] += D
end

function digest!(context::MD5_CTX)
    T = typeof(context)
    usedspace = context.bytecount % blocklen(T)
    usedspace += 1
    context.buffer[usedspace] = 0x80
    if usedspace <= 56
        while usedspace < 56
            usedspace += 1
            context.buffer[usedspace] = 0x00
        end
    else
        context.buffer[usedspace+1:end] = 0x00
        transform!(context)
        fill!(context.buffer, 0x00)
        usedspace = 56
    end
    @assert usedspace == 56
    B = typeof(context.bytecount)
    bitcount = context.bytecount * B(8)
    pbuf = Ptr{B}(pointer(context.buffer))
    index = 8
    unsafe_store!(pbuf, bitcount, index)
    transform!(context)
    reinterpret(UInt8, context.state)
end

end # end module MD5