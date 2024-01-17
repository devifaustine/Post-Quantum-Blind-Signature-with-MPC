from sphincs_params import *

# Implementation of tweakable hash function or thash
# 8-way parallel version of thash; takas 8x as much input and output

def thashx8(out0, out1, out2, out3, out4, out5, out6, out7,
            in0, in1, in2, in3, in4, in5, in6, in7, inblocks,
            ctx, addrx8):
    #if inblocks > 1:
        # this is for using SHA512, which we won't cover here
        #thashx8_512(out0, out1, out2, out3, out4, out5, out6, out7,
        #            in0, in1, in2, in3, in4, in5, in6, in7,
        #            inblocks, ctx, addrx8)
    #    return

    bufx8 = bytearray(8 * (SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N))
    outbufx8 = bytearray(8 * SPX_SHA256_OUTPUT_BYTES)
    bitmaskx8 = bytearray(8 * (inblocks * SPX_N))

    for i in range(8):
        bufx8[i*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
             (i+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] = \
            ctx.pub_seed + i*SPX_N
        bufx8[SPX_N + i*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
             SPX_N + (i+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] = \
            addrx8[i*8:(i+1)*8]

    mgf1x8(bitmaskx8, inblocks * SPX_N,
           bufx8[0*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (0+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           bufx8[1*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (1+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           bufx8[2*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (2+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           bufx8[3*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (3+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           bufx8[4*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (4+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           bufx8[5*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (5+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           bufx8[6*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (6+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           bufx8[7*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N):
                 (7+1)*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)],
           SPX_N + SPX_SHA256_ADDR_BYTES)


    for (i = 0; i < 8; i++) {
        memcpy(bufx8 + i*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
               ctx->pub_seed, SPX_N);
        memcpy(bufx8 + SPX_N +
                         i*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
                         addrx8 + i*8, SPX_SHA256_ADDR_BYTES);
    }

    mgf1x8(bitmaskx8, inblocks * SPX_N,
           bufx8 + 0*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 1*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 2*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 3*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 4*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 5*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 6*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           bufx8 + 7*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
           SPX_N + SPX_SHA256_ADDR_BYTES);

    for (i = 0; i < inblocks * SPX_N; i++) {
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                0*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in0[i] ^ bitmaskx8[i + 0*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                1*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in1[i] ^ bitmaskx8[i + 1*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                2*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in2[i] ^ bitmaskx8[i + 2*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                3*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in3[i] ^ bitmaskx8[i + 3*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                4*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in4[i] ^ bitmaskx8[i + 4*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                5*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in5[i] ^ bitmaskx8[i + 5*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                6*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in6[i] ^ bitmaskx8[i + 6*(inblocks * SPX_N)];
        bufx8[SPX_N + SPX_SHA256_ADDR_BYTES + i +
                7*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)] =
            in7[i] ^ bitmaskx8[i + 7*(inblocks * SPX_N)];
    }

    sha256x8_seeded(
        /* out */
        outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES,
        outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES,

        /* seed */
        ctx->state_seeded, 512,

        /* in */
        bufx8 + SPX_N + 0*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + SPX_N + 1*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + SPX_N + 2*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + SPX_N + 3*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + SPX_N + 4*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + SPX_N + 5*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + SPX_N + 6*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        bufx8 + SPX_N + 7*(SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N),
        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N /* len */
    );

    memcpy(out0, outbufx8 + 0*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out1, outbufx8 + 1*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out2, outbufx8 + 2*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out3, outbufx8 + 3*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out4, outbufx8 + 4*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out5, outbufx8 + 5*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out6, outbufx8 + 6*SPX_SHA256_OUTPUT_BYTES, SPX_N);
    memcpy(out7, outbufx8 + 7*SPX_SHA256_OUTPUT_BYTES, SPX_N);
}