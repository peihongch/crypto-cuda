#include <cstdint>

#include <cuda_runtime.h>

namespace cuda
{
    #define XTS_SECTOR_SIZE (512)

    #define HMAC_KEY_LENGTH (64)                           // 64B or 512b
    #define MAC_LENGTH (64)                                // 64B or 512b

    __device__ void xts_decrypt(uint8_t* key, uint32_t key_len, uint8_t* data, uint64_t tweak);
    __device__ void xts_encrypt(uint8_t* key, uint32_t key_len, uint8_t* data, uint64_t tweak);

    __global__ void global_xts_encrypt(uint8_t* key, uint32_t key_len, uint8_t* data, uint64_t tweak);
    __global__ void global_xts_decrypt(uint8_t* key, uint32_t key_len, uint8_t* data, uint64_t tweak);

    __global__ void xts_hmac_encrypt(uint8_t* key, uint32_t key_len, uint8_t* data, uint64_t tweak, uint8_t* mac);
    __global__ void xts_hmac_decrypt(uint8_t* key, uint32_t key_len, uint8_t* data, uint64_t tweak, uint8_t* mac);
}