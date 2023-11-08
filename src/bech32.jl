# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Stolen from https://github.com/fiatjaf/bech32

const BECH32_CHARSET::String = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


function bech32_polymod(values::Vector{<:Integer})
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ⊻ value
        for i in 0:4
            chk = chk ⊻ ((top >> i) & 1 > 0 ? generator[i+1] : 0)
        end
    end
    return chk
end

function bech32_checksum(hrp::String, data::Vector{UInt8})::Vector{UInt8}
    hrp_expanded = vcat([UInt8(c) >> 5 for c in hrp], 0x00, [UInt8(c) & 31 for c in hrp])
    values = vcat(hrp_expanded, data)
    polymod = bech32_polymod(vcat(values, fill(0x00, 6))) ⊻ 1

    # Extra paranthesis because of a slight difference in 
    # operation precedence for >> and * between python and julia
    # in python
    #     13451345 >> 3 * 6 = 51
    # in julia
    #     13451345 >> 3 * 6 = 10088508
    # but 13451345 >> (3 * 6) = 51
    checksum = UInt8[(polymod >> (5 * (5 - i))) & 31 for i in 0:5]
    return checksum
end

function bech32_encode(hrp::String, data::Vector{UInt8})::String
    ### checksum
    combined = vcat(data, bech32_checksum(hrp, data))
    return hrp * "1" * join(Char[BECH32_CHARSET[d+1] for d in combined])
end

function squash_8to5(x::Vector{UInt8}; pad=true)::Vector{UInt8}
    isempty(x) && return UInt8[]

    mask = 0x001f # 0b00000000 0b00011111
    squashed = UInt8[]

    mask_pos = 0
    i = length(x) - 1
    
    for k in 1:div(length(x) * 8 + 4, 5) # +(5 - 1) for ceildiv(x, 5)
        
        rmask = UInt8(0x00ff & mask)
        lmask = UInt8((0xff00 & mask) >> 8)

        # println(k)
        # println(bitstring(lmask), " ", bitstring(rmask))
        # println(bitstring((i > 0 ? x[i] : 0x00)), " ", bitstring(x[i+1]))
        # println(bitstring(bitrotate(lmask & (i > 0 ? x[i] : 0x00), -mask_pos)), " ", bitstring(bitrotate(rmask & x[i + 1], -mask_pos)))
        # println(bitstring(bitrotate(lmask & (i > 0 ? x[i] : 0x00), -mask_pos) | bitrotate(rmask & x[i + 1], -mask_pos)))
        # println()
        
        push!(squashed, bitrotate(lmask & (i > 0 ? x[i] : 0x00), -mask_pos) | bitrotate(rmask & x[i + 1], -mask_pos))

        mask = bitrotate(mask, 5)
        mask_pos += 5
        if mask_pos > 8
            mask = bitrotate(mask, 8)
            mask_pos = mod(mask_pos, 8)
            i -= 1
        end

    end    

    if !pad
        while length(squashed) > 0 && squashed[end] == 0x00
            pop!(squashed)
        end
    end

    return reverse!(squashed)
end


function squash_8to5_slow(x::Vector{UInt8}; pad=true)::Vector{UInt8}
    big_x = to_big(x)
    mask = 1 << 5 - 1
    squashed = UInt8[]
    while big_x > 0
        push!(squashed, UInt8(big_x & mask))
        big_x >>= 5
    end
    if pad
        target_bits = 8 * length(x)
        current_bits = 5 * length(squashed)
        padding_bits = target_bits - current_bits
        if padding_bits > 0
            append!(squashed, fill(0x00, div(padding_bits + 4, 5)))
        end
    end
    return reverse!(squashed)
end