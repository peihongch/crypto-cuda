/**
 * Reference:
 * 1. https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 * 2. https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */

#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "hash/xts.cuh"
#include "hash/aes.cuh"

#define TEXT_SIZE (4 * 1024 * 1024)
#define KEY_LENGTH (64)

using namespace cuda;

int main(int argc, char const* argv[])
{
    uint8_t* dev_text;
    std::vector<uint8_t> text(TEXT_SIZE, 1);
    uint8_t* dev_key;
    uint8_t key[KEY_LENGTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

    uint32_t key_bit[3] = {128, 192, 256};

    cudaMalloc((void**) &dev_text, TEXT_SIZE);
    cudaMalloc((void**) &dev_key, sizeof(key));
    cudaMemcpy(dev_text, text.data(), TEXT_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_key, key, sizeof(key), cudaMemcpyHostToDevice);

    // one aes_block per thread
    dim3 dimBlock(XTS_SECTOR_SIZE / AES_BLOCK_SIZE, 1);
    // one xts_sector per block
    dim3 dimGrid(TEXT_SIZE / XTS_SECTOR_SIZE, 1);

    uint32_t i;
    for (i = 0; i < sizeof(key_bit) / sizeof(key_bit[0]); ++i)
    {
        printf("key_bit %d: \n", key_bit[i]);
        printf(
            "\tinput  :   0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x "
            "0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6],
            text[7], text[8], text[9], text[10], text[11], text[12], text[13],
            text[14], text[15]);

        global_xts_encrypt<<<dimGrid, dimBlock>>>(dev_key, key_bit[i] * 2 / 8, dev_text, 0);
        cudaMemcpy(text.data(), dev_text, TEXT_SIZE, cudaMemcpyDeviceToHost);
        printf(
            "\tencrypt  :   0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x "
            "0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6],
            text[7], text[8], text[9], text[10], text[11], text[12], text[13],
            text[14], text[15]);

        global_xts_decrypt<<<dimGrid, dimBlock>>>(dev_key, key_bit[i] * 2 / 8, dev_text, 0);
        cudaMemcpy(text.data(), dev_text, TEXT_SIZE, cudaMemcpyDeviceToHost);
        printf(
            "\tdecrypt  :   0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x "
            "0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6],
            text[7], text[8], text[9], text[10], text[11], text[12], text[13],
            text[14], text[15]);
    }

    return 0;
}
