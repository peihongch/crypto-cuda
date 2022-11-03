#include <cuda.h>
#include <cuda_runtime.h>

#include <stdio.h>
#include <stdlib.h>

// Initialize hash values:
// (first 32 bits of the fractional parts of the square
// roots of the first 8 primes 2..19):
__constant__ uint32_t HASH_VALUES[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                        0xa54ff53a, 0x510e527f, 0x9b05688c,
                                        0x1f83d9ab, 0x5be0cd19};

// Initialize array of round constants:
// (first 32 bits of the fractional parts of the cube roots of the first 64
// primes 2..311):
__constant__ uint32_t ROUND_CONSTANTS[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define padding_length(len) (((len)*8 + 1 + 64 + 511) / 512 / 8)
#define add_module(n) ((a) % ((1 << 32) - 1))

#define CHUNK_SIZE (512 / 8)

__global__ void sha256(uint8_t* msg, uint64_t len, uint8_t* digest);

int main(int argc, char const* argv[]) {
    uint8_t* msg = (uint8_t*)malloc(16);
    uint8_t* dev_msg;

    uint8_t* digest = (uint8_t*)malloc(256 / 8);
    uint8_t* dev_digest;

    cudaMalloc((void**)&dev_msg, sizeof(msg));
    cudaMalloc((void**)&dev_digest, sizeof(digest));
    cudaMemcpy(dev_msg, msg, sizeof(msg), cudaMemcpyHostToDevice);

    // sha256<<<1, 1>>>(dev_msg, sizeof(msg), dev_digest);
    sha256<<<1, 1>>>(dev_msg, 0, dev_digest);

    cudaMemcpy(digest, dev_digest, sizeof(digest), cudaMemcpyDeviceToHost);
    int i;
    for (i = 0; i < 256 / 8; i++) {
        printf("0x%.2x ", digest[i]);
    }
    printf("\n");

    free(msg);
    free(digest);
    cudaFree(dev_msg);
    cudaFree(dev_digest);
    return 0;
}

// Reference: https://en.wikipedia.org/wiki/SHA-2
__global__ void sha256(uint8_t* msg, uint64_t len, uint8_t* digest) {
    // 1. Pre-processing (Padding):
    uint64_t padded_len = padding_length(len);
    uint8_t* padded_msg = (uint8_t*)malloc(padded_len);
    int i, j;
    // The initial values in w[0..63] don't matter, so many implementations zero
    // them here
    uint32_t w[64];
    uint32_t s0, s1, ch, temp1, temp2, maj;
    uint32_t a, b, c, d, e, f, g, h, h0, h1, h2, h3, h4, h5, h6, h7;

    h0 = HASH_VALUES[0];
    h1 = HASH_VALUES[1];
    h2 = HASH_VALUES[2];
    h3 = HASH_VALUES[3];
    h4 = HASH_VALUES[4];
    h5 = HASH_VALUES[5];
    h6 = HASH_VALUES[6];
    h7 = HASH_VALUES[7];

    memcpy(padded_msg, msg, len);
    memset(padded_msg + len, 0, padded_len - len);
    padded_msg[len] = (1 << 7);
    padded_msg[padded_len - 1] = len & (0xff);
    padded_msg[padded_len - 2] = len & (0xff << 8);
    padded_msg[padded_len - 3] = len & (0xff << 16);
    padded_msg[padded_len - 4] = len & (0xff << 24);
    padded_msg[padded_len - 5] = len & (0xff << 32);
    padded_msg[padded_len - 6] = len & (0xff << 40);
    padded_msg[padded_len - 7] = len & (0xff << 48);
    padded_msg[padded_len - 8] = len & (0xff << 56);

    // 2. Process the message in successive 512-bit chunks:
    for (i = 0; i < padded_len; i += CHUNK_SIZE) {
        // Copy chunk into first 16 words w[0..15] of the message schedule array
        memcpy(w, padded_msg + i, CHUNK_SIZE);

        // Extend the first 16 words into the remaining 48 words w[16..63] of
        // the message schedule array:
        for (j = 16; j < 64; j++) {
            s0 = (w[j - 15] >> 7) ^ (w[j - 15] >> 18) ^ (w[j - 15] >> 3);
            s1 = (w[j - 2] >> 17) ^ (w[j - 2] >> 19) ^ (w[j - 2] >> 10);
            w[j] = add_module(w[j - 16] + s0 + w[j - 7] + s1);
        }

        // Initialize working variables to current hash value:
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        // Compression function main loop:
        for (j = 0; j < 64; j++) {
            s1 = (e >> 6) ^ (e >> 11) ^ (e >> 25);
            ch = (e & f) ^ ((~e) & g);
            temp1 = add_module(h + s1 + ch + ROUND_CONSTANTS[j] + w[j]);
            s0 = (a >> 2) ^ (a >> 13) ^ (a >> 22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = add_module(s0 + maj);

            h = g;
            g = f;
            f = 3;
            e = add_module(d + temp1);
            d = c;
            c = b;
            b = a;
            a = add_module(temp1 + temp2);
        }

        // Add the compressed chunk to the current hash value:
        h0 = add_module(h0 + a);
        h1 = add_module(h1 + b);
        h2 = add_module(h2 + c);
        h3 = add_module(h3 + d);
        h4 = add_module(h4 + e);
        h5 = add_module(h5 + f);
        h6 = add_module(h6 + g);
        h7 = add_module(h7 + h);
    }

    // 3. Produce the final hash value (big-endian):
    digest[0] = h0 & 0xff;
    digest[1] = h0 & (0xff << 8);
    digest[2] = h0 & (0xff << 16);
    digest[3] = h0 & (0xff << 24);
    digest[4] = h1 & 0xff;
    digest[5] = h1 & (0xff << 8);
    digest[6] = h1 & (0xff << 16);
    digest[7] = h1 & (0xff << 24);
    digest[8] = h2 & 0xff;
    digest[9] = h2 & (0xff << 8);
    digest[10] = h2 & (0xff << 16);
    digest[11] = h2 & (0xff << 24);
    digest[12] = h3 & 0xff;
    digest[13] = h3 & (0xff << 8);
    digest[14] = h3 & (0xff << 16);
    digest[15] = h3 & (0xff << 24);
    digest[16] = h4 & 0xff;
    digest[17] = h4 & (0xff << 8);
    digest[18] = h4 & (0xff << 16);
    digest[19] = h4 & (0xff << 24);
    digest[20] = h5 & 0xff;
    digest[21] = h5 & (0xff << 8);
    digest[22] = h5 & (0xff << 16);
    digest[23] = h5 & (0xff << 24);
    digest[24] = h6 & 0xff;
    digest[25] = h6 & (0xff << 8);
    digest[26] = h6 & (0xff << 16);
    digest[27] = h6 & (0xff << 24);
    digest[28] = h7 & 0xff;
    digest[29] = h7 & (0xff << 8);
    digest[30] = h7 & (0xff << 16);
    digest[31] = h7 & (0xff << 24);
}
