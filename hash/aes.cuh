#pragma once

#include <cuda_runtime.h>
#include <cstdint>

namespace cuda
{
    #define AES_KEY_LENGTH (64)                            // 64B or 512b
    #define AES_MAX_KEYLENGTH (15 * 16)
    #define AES_BLOCK_SIZE (16)

    __device__ void aes_encrypt(uint32_t nr, const uint8_t* key, uint8_t text[AES_BLOCK_SIZE]);

    __device__ void aes_decrypt(uint32_t nr, const uint8_t* key, uint8_t text[AES_BLOCK_SIZE]);
}