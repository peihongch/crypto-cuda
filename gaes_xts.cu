/**
 * Reference:
 * 1. https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * 2. https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */

#include <cuda.h>
#include <cuda_runtime.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define XTS_SECTOR_SIZE 512

#define TEXT_SIZE (1024 * 16)
#define KEY_LENGTH (64)

typedef struct {
    uint32_t nr;   // rounds
    uint32_t* rk;  // round_key
    uint32_t buf[(AES_BLOCK_SIZE + 1)
                 << 2];  // store round_keys, each block is 4 bytes
} aes_context;

__device__ void aes_set_key(aes_context* ctx,
                            const uint8_t* key,
                            uint32_t key_bit);

__device__ void aes_encrypt(aes_context* ctx,
                            uint8_t cipher_text[16],
                            const uint8_t text[16]);

__device__ void aes_decrypt(aes_context* ctx,
                            uint8_t text[16],
                            const uint8_t cipher_text[16]);

__global__ void xts_encrypt(uint8_t* key,
                            uint32_t key_len,
                            uint8_t* cipher_text,
                            const uint8_t* text,
                            const uint64_t tweak);

__global__ void xts_decrypt(uint8_t* key,
                            uint32_t key_len,
                            uint8_t* text,
                            const uint8_t* cipher_text,
                            const uint64_t tweak);

int main(int argc, char const* argv[]) {
    uint8_t* dev_ret_text;
    uint8_t* ret_text = (uint8_t*)malloc(TEXT_SIZE);
    uint8_t* dev_cipher_text;
    uint8_t* cipher_text = (uint8_t*)malloc(TEXT_SIZE);
    uint8_t* dev_text;
    uint8_t* text = (uint8_t*)malloc(TEXT_SIZE);
    uint8_t* dev_key;
    uint8_t key[KEY_LENGTH] = {
        0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad,
        0xd6, 0xaf, 0x7f, 0x67, 0x98, 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9,
        0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98, 0x0f,
        0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6,
        0xaf, 0x7f, 0x67, 0x98, 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8,
        0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98};

    uint32_t key_bit[3] = {128, 192, 256};
    memset(text, 1, TEXT_SIZE);
    memset(ret_text, 2, TEXT_SIZE);
    memset(cipher_text, 3, TEXT_SIZE);

    cudaMalloc((void**)&dev_ret_text, TEXT_SIZE);
    cudaMalloc((void**)&dev_text, TEXT_SIZE);
    cudaMalloc((void**)&dev_cipher_text, TEXT_SIZE);
    cudaMalloc((void**)&dev_key, sizeof(key));
    cudaMemcpy(dev_text, text, TEXT_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_key, key, sizeof(key), cudaMemcpyHostToDevice);

    // one aes_block per thread
    dim3 dimBlock(XTS_SECTOR_SIZE / AES_BLOCK_SIZE, 1);
    // one xts_sector per block
    dim3 dimGrid(TEXT_SIZE / XTS_SECTOR_SIZE, 1);

    uint32_t i;
    for (i = 0; i < sizeof(key_bit) / sizeof(key_bit[0]); ++i) {
        xts_encrypt<<<dimGrid, dimBlock>>>(dev_key, key_bit[i] * 2,
                                           dev_cipher_text, dev_text, 0);
        xts_decrypt<<<dimGrid, dimBlock>>>(dev_key, key_bit[i] * 2,
                                           dev_ret_text, dev_cipher_text, 0);

        cudaMemcpy(ret_text, dev_ret_text, TEXT_SIZE, cudaMemcpyDeviceToHost);
        cudaMemcpy(cipher_text, dev_cipher_text, TEXT_SIZE,
                   cudaMemcpyDeviceToHost);

        printf("key_bit %d: \n", key_bit[i]);
        printf(
            "\tinput  :   0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x "
            "0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6],
            text[7], text[8], text[9], text[10], text[11], text[12], text[13],
            text[14], text[15]);
        printf(
            "\tencrypt:  0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x "
            "0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
            cipher_text[0], cipher_text[1], cipher_text[2], cipher_text[3],
            cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7],
            cipher_text[8], cipher_text[9], cipher_text[10], cipher_text[11],
            cipher_text[12], cipher_text[13], cipher_text[14], cipher_text[15]);
        printf(
            "\tdecrypt:   0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x "
            "0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
            ret_text[0], ret_text[1], ret_text[2], ret_text[3], ret_text[4],
            ret_text[5], ret_text[6], ret_text[7], ret_text[8], ret_text[9],
            ret_text[10], ret_text[11], ret_text[12], ret_text[13],
            ret_text[14], ret_text[15]);
    }
    return 0;
}

__device__ static const uint8_t S_BOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

__device__ static const uint8_t INV_S_BOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

__device__ static const uint8_t MIX[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                             {0x01, 0x02, 0x03, 0x01},
                                             {0x01, 0x01, 0x02, 0x03},
                                             {0x03, 0x01, 0x01, 0x02}};

__device__ static const uint8_t INV_MIX[4][4] = {{0x0e, 0x0b, 0x0d, 0x09},
                                                 {0x09, 0x0e, 0x0b, 0x0d},
                                                 {0x0d, 0x09, 0x0e, 0x0b},
                                                 {0x0b, 0x0d, 0x09, 0x0e}};

__device__ static const uint32_t RCON[10] = {
    0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010,
    0x00000020, 0x00000040, 0x00000080, 0x0000001B, 0x00000036};

#ifndef GET_UINT32
#define GET_UINT32(n, b, i)                                                    \
    do {                                                                       \
        (n) = ((uint32_t)(b)[(i)]) | ((uint32_t)(b)[(i) + 1] << 8) |           \
              ((uint32_t)(b)[(i) + 2] << 16) | ((uint32_t)(b)[(i) + 3] << 24); \
    } while (0)
#endif

#define ROTL8(x) (((x) << 24) | ((x) >> 8))
#define ROTL16(x) (((x) << 16) | ((x) >> 16))
#define ROTL24(x) (((x) << 8) | ((x) >> 24))

#define SUB_WORD(x)                                                            \
    (((uint32_t)S_BOX[(x)&0xFF]) | ((uint32_t)S_BOX[((x) >> 8) & 0xFF] << 8) | \
     ((uint32_t)S_BOX[((x) >> 16) & 0xFF] << 16) |                             \
     ((uint32_t)S_BOX[((x) >> 24) & 0xFF] << 24))

__device__ static void transport(uint8_t state[AES_BLOCK_SIZE]) {
    uint8_t new_state[4][4];
    int r, c;
    for (r = 0; r < 4; ++r)
        for (c = 0; c < 4; ++c)
            new_state[r][c] = state[(c << 2) + r];
    memcpy(state, new_state, sizeof(new_state));
}

__device__ static void add_round_key(uint8_t state[AES_BLOCK_SIZE],
                                     const uint8_t key[AES_BLOCK_SIZE]) {
    int i;
    for (i = 0; i < AES_BLOCK_SIZE; ++i)
        state[i] ^= key[i];
}

__device__ static void _sub_bytes(uint8_t state[AES_BLOCK_SIZE],
                                  const uint8_t* box) {
    int i;
    for (i = 0; i < AES_BLOCK_SIZE; ++i)
        state[i] = box[state[i]];
}

#define sub_bytes(state) _sub_bytes(state, S_BOX)
#define inv_sub_bytes(state) _sub_bytes(state, INV_S_BOX)

#define _shift_rows(state, OP1, OP2, OP3)                         \
    do {                                                          \
        transport(state);                                         \
        *(uint32_t*)(state + 4) = OP1(*(uint32_t*)(state + 4));   \
        *(uint32_t*)(state + 8) = OP2(*(uint32_t*)(state + 8));   \
        *(uint32_t*)(state + 12) = OP3(*(uint32_t*)(state + 12)); \
        transport(state);                                         \
    } while (0)

#define shift_rows(state) _shift_rows(state, ROTL8, ROTL16, ROTL24)
#define inv_shift_rows(state) _shift_rows(state, ROTL24, ROTL16, ROTL8)

__device__ static uint8_t GF_256_multiply(uint8_t a, uint8_t b) {
    uint8_t t[8] = {a};
    uint8_t ret = 0x00;
    int i = 0;
    for (i = 1; i < 8; ++i) {
        t[i] = t[i - 1] << 1;
        if (t[i - 1] & 0x80)
            t[i] ^= 0x1b;
    }
    for (i = 0; i < 8; ++i)
        ret ^= (((b >> i) & 0x01) * t[i]);
    return ret;
}

__device__ static void _mix_columns(uint8_t state[AES_BLOCK_SIZE],
                                    const uint8_t matrix[][4]) {
    uint8_t new_state[AES_BLOCK_SIZE] = {0};
    int r, c, i;
    for (r = 0; r < 4; ++r)
        for (c = 0; c < 4; ++c)
            for (i = 0; i < 4; ++i)
                new_state[(c << 2) + r] ^=
                    GF_256_multiply(matrix[r][i], state[(c << 2) + i]);
    memcpy(state, new_state, sizeof(new_state));
}

#define mix_columns(state) _mix_columns(state, MIX)
#define inv_mix_columns(state) _mix_columns(state, INV_MIX)

__device__ static void aes_round(uint8_t state[AES_BLOCK_SIZE],
                                 const uint8_t rk[AES_BLOCK_SIZE]) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, rk);
}

__device__ static void aes_inv_round(uint8_t state[AES_BLOCK_SIZE],
                                     const uint8_t inv_rk[AES_BLOCK_SIZE]) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, inv_rk);
    inv_mix_columns(state);
}

__device__ static void aes_final_round(uint8_t state[AES_BLOCK_SIZE],
                                       const uint8_t rk[AES_BLOCK_SIZE]) {
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk);
}

__device__ static void inv_final_round(uint8_t state[AES_BLOCK_SIZE],
                                       const uint8_t inv_rk[AES_BLOCK_SIZE]) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, inv_rk);
}

__device__ static void key_expansion(aes_context* ctx, const uint8_t* key) {
    uint32_t nk = ctx->nr - 6;
    uint32_t ek = (ctx->nr + 1) << 2;
    uint32_t* rk = ctx->rk;

    uint32_t i = 0;
    do {
        GET_UINT32(rk[i], key, i << 2);
    } while (++i < nk);
    do {
        uint32_t t = rk[i - 1];
        if ((i % nk) == 0)
            t = SUB_WORD(ROTL8(t)) ^ RCON[i / nk - 1];
        else if (nk == 8 && (i % nk) == 4)
            t = SUB_WORD(t);
        rk[i] = rk[i - nk] ^ t;
    } while (++i < ek);
}

__device__ void aes_set_key(aes_context* ctx,
                            const uint8_t* key,
                            uint32_t key_bit) {
    switch (key_bit) {
        case 128:
        case 16:
            ctx->nr = 10;
            break;
        case 192:
        case 24:
            ctx->nr = 12;
            break;
        case 256:
        case 32:
            ctx->nr = 14;
            break;
        default:
            return;
    }
    ctx->rk = ctx->buf;
    key_expansion(ctx, key);
}

__device__ void aes_encrypt(aes_context* ctx,
                            uint8_t cipher_text[AES_BLOCK_SIZE],
                            const uint8_t text[AES_BLOCK_SIZE]) {
    uint32_t nr = ctx->nr;
    uint32_t* rk = ctx->rk;
    uint8_t* state = cipher_text;

    if (text != cipher_text)
        memcpy(state, text, AES_BLOCK_SIZE);

    add_round_key(state, (const uint8_t*)rk);
    uint32_t i;
    for (i = 1; i < nr; ++i)
        aes_round(state, (const uint8_t*)(rk + (i << 2)));
    aes_final_round(state, (const uint8_t*)(rk + (nr << 2)));
}

__device__ void aes_decrypt(aes_context* ctx,
                            uint8_t text[AES_BLOCK_SIZE],
                            const uint8_t cipher_text[AES_BLOCK_SIZE]) {
    uint32_t nr = ctx->nr;
    uint32_t* inv_rk = ctx->rk;
    uint8_t* state = text;
    memcpy(state, cipher_text, AES_BLOCK_SIZE);

    add_round_key(state, (const uint8_t*)(inv_rk + (nr << 2)));
    uint32_t i;
    for (i = nr - 1; i > 0; --i)
        aes_inv_round(state, (const uint8_t*)(inv_rk + (i << 2)));
    inv_final_round(state, (const uint8_t*)inv_rk);
}

///////////////////////////////// XTS /////////////////////////////////////////

#define gf128mul_dat(q)                                                    \
    {                                                                      \
        q(0x00), q(0x01), q(0x02), q(0x03), q(0x04), q(0x05), q(0x06),     \
            q(0x07), q(0x08), q(0x09), q(0x0a), q(0x0b), q(0x0c), q(0x0d), \
            q(0x0e), q(0x0f), q(0x10), q(0x11), q(0x12), q(0x13), q(0x14), \
            q(0x15), q(0x16), q(0x17), q(0x18), q(0x19), q(0x1a), q(0x1b), \
            q(0x1c), q(0x1d), q(0x1e), q(0x1f), q(0x20), q(0x21), q(0x22), \
            q(0x23), q(0x24), q(0x25), q(0x26), q(0x27), q(0x28), q(0x29), \
            q(0x2a), q(0x2b), q(0x2c), q(0x2d), q(0x2e), q(0x2f), q(0x30), \
            q(0x31), q(0x32), q(0x33), q(0x34), q(0x35), q(0x36), q(0x37), \
            q(0x38), q(0x39), q(0x3a), q(0x3b), q(0x3c), q(0x3d), q(0x3e), \
            q(0x3f), q(0x40), q(0x41), q(0x42), q(0x43), q(0x44), q(0x45), \
            q(0x46), q(0x47), q(0x48), q(0x49), q(0x4a), q(0x4b), q(0x4c), \
            q(0x4d), q(0x4e), q(0x4f), q(0x50), q(0x51), q(0x52), q(0x53), \
            q(0x54), q(0x55), q(0x56), q(0x57), q(0x58), q(0x59), q(0x5a), \
            q(0x5b), q(0x5c), q(0x5d), q(0x5e), q(0x5f), q(0x60), q(0x61), \
            q(0x62), q(0x63), q(0x64), q(0x65), q(0x66), q(0x67), q(0x68), \
            q(0x69), q(0x6a), q(0x6b), q(0x6c), q(0x6d), q(0x6e), q(0x6f), \
            q(0x70), q(0x71), q(0x72), q(0x73), q(0x74), q(0x75), q(0x76), \
            q(0x77), q(0x78), q(0x79), q(0x7a), q(0x7b), q(0x7c), q(0x7d), \
            q(0x7e), q(0x7f), q(0x80), q(0x81), q(0x82), q(0x83), q(0x84), \
            q(0x85), q(0x86), q(0x87), q(0x88), q(0x89), q(0x8a), q(0x8b), \
            q(0x8c), q(0x8d), q(0x8e), q(0x8f), q(0x90), q(0x91), q(0x92), \
            q(0x93), q(0x94), q(0x95), q(0x96), q(0x97), q(0x98), q(0x99), \
            q(0x9a), q(0x9b), q(0x9c), q(0x9d), q(0x9e), q(0x9f), q(0xa0), \
            q(0xa1), q(0xa2), q(0xa3), q(0xa4), q(0xa5), q(0xa6), q(0xa7), \
            q(0xa8), q(0xa9), q(0xaa), q(0xab), q(0xac), q(0xad), q(0xae), \
            q(0xaf), q(0xb0), q(0xb1), q(0xb2), q(0xb3), q(0xb4), q(0xb5), \
            q(0xb6), q(0xb7), q(0xb8), q(0xb9), q(0xba), q(0xbb), q(0xbc), \
            q(0xbd), q(0xbe), q(0xbf), q(0xc0), q(0xc1), q(0xc2), q(0xc3), \
            q(0xc4), q(0xc5), q(0xc6), q(0xc7), q(0xc8), q(0xc9), q(0xca), \
            q(0xcb), q(0xcc), q(0xcd), q(0xce), q(0xcf), q(0xd0), q(0xd1), \
            q(0xd2), q(0xd3), q(0xd4), q(0xd5), q(0xd6), q(0xd7), q(0xd8), \
            q(0xd9), q(0xda), q(0xdb), q(0xdc), q(0xdd), q(0xde), q(0xdf), \
            q(0xe0), q(0xe1), q(0xe2), q(0xe3), q(0xe4), q(0xe5), q(0xe6), \
            q(0xe7), q(0xe8), q(0xe9), q(0xea), q(0xeb), q(0xec), q(0xed), \
            q(0xee), q(0xef), q(0xf0), q(0xf1), q(0xf2), q(0xf3), q(0xf4), \
            q(0xf5), q(0xf6), q(0xf7), q(0xf8), q(0xf9), q(0xfa), q(0xfb), \
            q(0xfc), q(0xfd), q(0xfe), q(0xff)                             \
    }

#define xx(p, q) 0x##p##q

// #define xda_lle(i) ( \
// 	(i & 0x80 ? xx(e1, 00) : 0) ^ (i & 0x40 ? xx(70, 80) : 0) ^ \
// 	(i & 0x20 ? xx(38, 40) : 0) ^ (i & 0x10 ? xx(1c, 20) : 0) ^ \
// 	(i & 0x08 ? xx(0e, 10) : 0) ^ (i & 0x04 ? xx(07, 08) : 0) ^ \
// 	(i & 0x02 ? xx(03, 84) : 0) ^ (i & 0x01 ? xx(01, c2) : 0) \
// )

#define xda_bbe(i)                                               \
    ((i & 0x80 ? xx(43, 80) : 0) ^ (i & 0x40 ? xx(21, c0) : 0) ^ \
     (i & 0x20 ? xx(10, e0) : 0) ^ (i & 0x10 ? xx(08, 70) : 0) ^ \
     (i & 0x08 ? xx(04, 38) : 0) ^ (i & 0x04 ? xx(02, 1c) : 0) ^ \
     (i & 0x02 ? xx(01, 0e) : 0) ^ (i & 0x01 ? xx(00, 87) : 0))

typedef unsigned short u16;

// __device__ static const u16 gf128mul_table_lle[256] = gf128mul_dat(xda_lle);
__device__ static const u16 gf128mul_table_bbe[256] = gf128mul_dat(xda_bbe);

__device__ void gf128mul_x_ble(const uint8_t r[16], const uint8_t x[16]) {
    uint64_t a = *(uint64_t*)x;
    uint64_t b = *(uint64_t*)(x + 8);
    uint64_t _tt = gf128mul_table_bbe[b >> 63];

    *(uint64_t*)r = _tt ^ (a << 1);
    *(uint64_t*)(r + 8) = (b << 1) ^ (a >> 63);
}

__device__ void be128_xor(uint8_t* r, const uint8_t* p, const uint8_t* q) {
    unsigned int i;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        r[i] = p[i] ^ q[i];
    }
}

__global__ void xts_encrypt(uint8_t* key,
                            uint32_t key_len,
                            uint8_t* cipher_text,
                            const uint8_t* text,
                            const uint64_t tweak) {
    unsigned int nblocks = blockDim.x;
    uint8_t* t;
    const uint8_t* src =
        text + AES_BLOCK_SIZE * (blockIdx.x * blockDim.x + threadIdx.x);
    uint8_t* dst =
        cipher_text + AES_BLOCK_SIZE * (blockIdx.x * blockDim.x + threadIdx.x);
    unsigned int i;
    uint8_t tweak_buf[XTS_SECTOR_SIZE];

    aes_context* tweak_ctx = (aes_context*)malloc(sizeof(aes_context));
    aes_context* crypt_ctx = (aes_context*)malloc(sizeof(aes_context));

    aes_set_key(crypt_ctx, key, key_len / 2);
    aes_set_key(tweak_ctx, key + (key_len / 2) / sizeof(uint8_t), key_len / 2);

    /* calculate first value of T */
    *((uint64_t*)tweak_buf) = tweak + threadIdx.x;
    *(((uint64_t*)tweak_buf) + 1) = 0;
    aes_encrypt(tweak_ctx, tweak_buf, tweak_buf);

    i = 0;
    goto first;

    for (i = 0; i < nblocks; i++) {
        gf128mul_x_ble(tweak_buf + i * AES_BLOCK_SIZE, t);
    first:
        t = tweak_buf + i * AES_BLOCK_SIZE;
    }

    /* PP <- T xor P */
    be128_xor(dst, tweak_buf + AES_BLOCK_SIZE * threadIdx.x, src);
    /* CC <- E(Key2,PP) */
    aes_encrypt(crypt_ctx, dst, dst);
    /* C <- C xor CC */
    be128_xor(dst, dst, tweak_buf + AES_BLOCK_SIZE * threadIdx.x);
}

__global__ void xts_decrypt(uint8_t* key,
                            uint32_t key_len,
                            uint8_t* text,
                            const uint8_t* cipher_text,
                            const uint64_t tweak) {
    unsigned int nblocks = blockDim.x;
    uint8_t* t;
    const uint8_t* src =
        cipher_text + AES_BLOCK_SIZE * (blockIdx.x * blockDim.x + threadIdx.x);
    uint8_t* dst =
        text + AES_BLOCK_SIZE * (blockIdx.x * blockDim.x + threadIdx.x);
    unsigned int i;
    uint8_t tweak_buf[XTS_SECTOR_SIZE];

    aes_context* tweak_ctx = (aes_context*)malloc(sizeof(aes_context));
    aes_context* crypt_ctx = (aes_context*)malloc(sizeof(aes_context));

    aes_set_key(crypt_ctx, key, key_len / 2);
    aes_set_key(tweak_ctx, key + (key_len / 2) / sizeof(uint8_t), key_len / 2);

    /* calculate first value of T */
    *((uint64_t*)tweak_buf) = tweak + threadIdx.x;
    *(((uint64_t*)tweak_buf) + 1) = 0;
    aes_encrypt(tweak_ctx, tweak_buf, tweak_buf);

    i = 0;
    goto first;

    for (i = 0; i < nblocks; i++) {
        gf128mul_x_ble(tweak_buf + i * AES_BLOCK_SIZE, t);
    first:
        t = tweak_buf + i * AES_BLOCK_SIZE;
    }

    /* PP <- T xor P */
    be128_xor(dst, tweak_buf + AES_BLOCK_SIZE * threadIdx.x, src);
    /* CC <- E(Key2,PP) */
    aes_decrypt(crypt_ctx, dst, dst);
    /* C <- C xor CC */
    be128_xor(dst, dst, tweak_buf + AES_BLOCK_SIZE * threadIdx.x);
}
