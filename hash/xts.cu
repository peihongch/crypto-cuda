#include "xts.cuh"
#include "aes.cuh"

#include "sha.h"

namespace cuda
{
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

    #define xda_bbe(i)                                               \
        ((i & 0x80 ? xx(43, 80) : 0) ^ (i & 0x40 ? xx(21, c0) : 0) ^ \
         (i & 0x20 ? xx(10, e0) : 0) ^ (i & 0x10 ? xx(08, 70) : 0) ^ \
         (i & 0x08 ? xx(04, 38) : 0) ^ (i & 0x04 ? xx(02, 1c) : 0) ^ \
         (i & 0x02 ? xx(01, 0e) : 0) ^ (i & 0x01 ? xx(00, 87) : 0))

    __constant__ uint16_t gf128mul_table_bbe[256] = gf128mul_dat(xda_bbe);

    #define gf128mul_x_ble(r, x)                                  \
        (*r = gf128mul_table_bbe[(*(x + 1)) >> 63] ^ ((*x) << 1), \
         *(r + 1) = ((*(x + 1)) << 1) ^ ((*x) >> 63))

    #define be128_xor(r, p, q) ((r)[0] = (p)[0] ^ (q)[0], (r)[1] = (p)[1] ^ (q)[1])

    __device__ void xts_encrypt(uint8_t* key, uint32_t key_len, uint8_t* data, const uint64_t tweak)
    {
        uint32_t nrounds = key_len / 2 / 4 + 6;
        uint64_t tweak_buf[AES_BLOCK_SIZE / sizeof(uint64_t)] = {tweak + blockIdx.x,
                                                                 0};

        data = data + AES_BLOCK_SIZE * (blockIdx.x * blockDim.x + threadIdx.x);

        /* calculate first value of T */
        aes_encrypt(nrounds, key + key_len / 2, (uint8_t*) tweak_buf);

    #pragma unroll
        for (uint32_t i = 1; i <= threadIdx.x; i++)
        {
            gf128mul_x_ble(tweak_buf, tweak_buf);
        }

        /* PP <- T xor P */
        be128_xor((uint64_t*) data, tweak_buf, (uint64_t*) data);
        /* CC <- E(Key2,PP) */
        aes_encrypt(nrounds, key, data);
        /* C <- C xor CC */
        be128_xor((uint64_t*) data, (uint64_t*) data, tweak_buf);
    }

    __device__ void xts_decrypt(uint8_t* key, uint32_t key_len, uint8_t* data, const uint64_t tweak)
    {
        uint32_t nrounds = key_len / 2 / 4 + 6;
        uint64_t tweak_buf[AES_BLOCK_SIZE / sizeof(uint64_t)] = {tweak + blockIdx.x, 0};

        data = data + AES_BLOCK_SIZE * (blockIdx.x * blockDim.x + threadIdx.x);

        /* calculate first value of T */
        aes_encrypt(nrounds, key + key_len / 2, (uint8_t*) tweak_buf);

    #pragma unroll
        for (uint32_t i = 1; i <= threadIdx.x; i++)
        {
            gf128mul_x_ble(tweak_buf, tweak_buf);
        }

        /* PP <- T xor P */
        be128_xor((uint64_t*) data, tweak_buf, (uint64_t*) data);
        /* CC <- E(Key2,PP) */
        aes_decrypt(nrounds, key, data);
        /* C <- C xor CC */
        be128_xor((uint64_t*) data, (uint64_t*) data, tweak_buf);
    }

    __global__ void global_xts_encrypt(uint8_t* key, uint32_t key_len, uint8_t* data, const uint64_t tweak)
    {
        xts_encrypt(key, key_len, data, tweak);
    }

    __global__ void global_xts_decrypt(uint8_t* key, uint32_t key_len, uint8_t* data, const uint64_t tweak)
    {
        xts_decrypt(key, key_len, data, tweak);
    }

    __device__ void hmac_sha(const unsigned char* text, int text_len, const unsigned char* aad, int aad_len, const unsigned char* key, int key_len, uint8_t digest[USHAMaxHashSize])
    {
        HMACContext ctx;
        hmacReset(&ctx, SHA512, key, key_len) || hmacInput(&ctx, aad, aad_len) ||
        hmacInput(&ctx, text, text_len) || hmacResult(&ctx, digest);
    }

    /**
     * A cryptographic unit that implements a cryptographic mode
     * within the XTS-HMAC family shall use the XTS-AES-256 procedure
     * as specified in IEEE Std 1619 for confidentiality, and HMAC-SHA-512
     * as specified by NIST FIPS 198 and NIST FIPS 180-2 to generate the MAC,
     * with the following specifications:
     * a) The cipher key length shall be 1024 b (128 B), consisting of
     *   the concatenation of the following parts, in order:
     *   1) An AES key that is 512 b (64 B) in length, used as input into
     *      the XTS-AES-256 procedure (see IEEE Std 1619).
     *   2) An HMAC key that is 512 b (64 B) in length, used as input into
     *      the HMAC-SHA-512 procedure.
     * b) The cryptographic unit shall compute IVs according to 6.5.
     *   The IV is used as the tweak specified in IEEE Std 1619.
     * c) The IV length shall be 128 b (16 B).
     * d) The resulting MAC shall be 512 b (64 B) in length.
     */
    __global__ void xts_hmac_encrypt(uint8_t* key, uint32_t key_len, uint8_t* data, const uint64_t tweak, uint8_t* mac)
    {
        xts_encrypt(key, AES_KEY_LENGTH, data, tweak);

        uint64_t aad[2] = {tweak + blockIdx.x, 0};
        uint8_t* data_block = data + XTS_SECTOR_SIZE * blockIdx.x;
        hmac_sha(data_block, XTS_SECTOR_SIZE, (unsigned char*) aad, sizeof(aad), key + AES_KEY_LENGTH, HMAC_KEY_LENGTH, mac + MAC_LENGTH * blockIdx.x);
    }

    __global__ void xts_hmac_decrypt(uint8_t* key, uint32_t key_len,  uint8_t* data, const uint64_t tweak, uint8_t* mac)
    {
        uint64_t aad[2] = {tweak + blockIdx.x, 0};
        uint8_t* data_block = data + XTS_SECTOR_SIZE * blockIdx.x;
        hmac_sha(data_block, XTS_SECTOR_SIZE, (unsigned char*) aad, sizeof(aad), key + AES_KEY_LENGTH, HMAC_KEY_LENGTH, mac + MAC_LENGTH * blockIdx.x);

        xts_decrypt(key, AES_KEY_LENGTH, data, tweak);
    }
}