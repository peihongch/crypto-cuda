#include "sha.h"
#include <device_launch_parameters.h>

#include <cstdio>
#include <cstring>

using namespace cuda;

#define TEST_BLOCK_LEN (512)
#define TEST_BLOCK_COUNT (32 * 1024 / TEST_BLOCK_LEN)

int main(int argc, char const* argv[])
{
    uint32_t i;
    uint8_t blocks[TEST_BLOCK_COUNT * TEST_BLOCK_LEN]{0};
    uint8_t* dev_blocks = nullptr;
    uint8_t new_blocks[TEST_BLOCK_COUNT * TEST_BLOCK_LEN]{0};
    uint8_t* dev_new_blocks = nullptr;
    uint8_t digest[USHAMaxHashSize]{0};
    uint8_t* dev_digest = nullptr;

    for (i = 0; i < TEST_BLOCK_COUNT; i++)
    {
        memset(blocks + i * TEST_BLOCK_LEN, i + 1, TEST_BLOCK_LEN);
    }
    for (i = 0; i < TEST_BLOCK_COUNT; i++)
    {
        memset(blocks + i * TEST_BLOCK_LEN, TEST_BLOCK_LEN - i, TEST_BLOCK_LEN);
    }

    cudaMalloc((void**) &dev_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN);
    cudaMalloc((void**) &dev_new_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN);
    cudaMalloc((void**) &dev_digest, USHAMaxHashSize);
    cudaMemcpy(dev_blocks, blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_new_blocks, new_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_digest, digest, USHAMaxHashSize, cudaMemcpyHostToDevice);

    // one aes_block per thread
    dim3 dimBlock(32, 1);
    // one xts_sector per block
    dim3 dimGrid(1, 1);

    IHASHInit<<<dimGrid, dimBlock>>>(SHA256, TEST_BLOCK_LEN, dev_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, dev_digest);
    cudaMemcpy(digest, dev_digest, USHAMaxHashSize, cudaMemcpyDeviceToHost);
    printf("initial    :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
            digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15]);

    cudaMemcpy(dev_blocks, blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, cudaMemcpyHostToDevice);
    IHASHUpdate<<<dimGrid, dimBlock>>>(SHA256, TEST_BLOCK_LEN, dev_blocks, dev_new_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, dev_digest);
    cudaMemcpy(digest, dev_digest, USHAMaxHashSize, cudaMemcpyDeviceToHost);
    printf("updated    :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
            digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15]);

    IHASHInit<<<dimGrid, dimBlock>>>(SHA256, TEST_BLOCK_LEN, dev_new_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, dev_digest);
    cudaMemcpy(digest, dev_digest, USHAMaxHashSize, cudaMemcpyDeviceToHost);
    printf("onepass    :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
            digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15]);

    return 0;
}
