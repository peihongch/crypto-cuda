/*
 *  Description:
 *     This file implements an incremental hash function based on the SHA
 * algorithms.
 */

#include "sha.h"

__device__ int ISHAReset(ISHAContext* ctx,
                         SHAversion whichSha,
                         uint8_t state[USHAMaxHashSize]) {
    int i;
    if (ctx) {
        ctx->whichSha = whichSha;
        if (state) {
            ctx->state = state;
        } else {
            ctx->state = ctx->intermediate_hash;
            for (i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x) {
                ctx->state[i] = 0;
            }
        }
        return USHAReset(&ctx->shaContext, whichSha);
    } else {
        return shaNull;
    }
}

__device__ int ISHAInput(ISHAContext* ctx,
                         const uint8_t* bytes,
                         unsigned int bytecount,
                         const uint32_t index) {
    int err, i;
    if (ctx) {
        // tmp = Hash(data || ID)
        err = USHAReset(&ctx->shaContext, ctx->whichSha) ||
              USHAInput(&ctx->shaContext, bytes, bytecount) ||
              USHAInput(&ctx->shaContext, (uint8_t*)&index, sizeof(index)) ||
              USHAResult(&ctx->shaContext, ctx->tmp);
        if (err) {
            return err;
        }

        // h = h XOR tmp
        // for (i = 0; i < USHAMaxHashSize; i++) {
        //     ctx->state[i] ^= ctx->tmp[i];
        // }
        // FIXME: how to make it more general?
        for (i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x) {
            ctx->state[i] ^= ctx->tmp[i];
        }
        return shaSuccess;
    } else {
        return shaNull;
    }
}

__device__ int ISHAUpdate(ISHAContext* ctx,
                          const uint8_t* oldbytes,
                          const uint8_t* newbytes,
                          unsigned int bytecount,
                          const uint32_t index) {
    if (ctx) {
        // h = h XOR Hash(olddata || ID)
        // XOR Hash(newdata || ID) into state
        return ISHAInput(ctx, oldbytes, bytecount, index) ||
               // XOR Hash(newdata || ID) into state
               ISHAInput(ctx, newbytes, bytecount, index);
    } else {
        return shaNull;
    }
}

__device__ int ISHAResult(ISHAContext* ctx,
                          uint8_t Message_Digest[USHAMaxHashSize]) {
    int i;
    if (ctx) {
        for (i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x) {
            Message_Digest[i] = ctx->state[i];
        }
        return shaSuccess;
    } else {
        return shaNull;
    }
}

#ifdef ISHA_TEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_BLOCK_LEN (512)
#define TEST_BLOCK_COUNT (32 * 1024 / TEST_BLOCK_LEN)

__global__ void ihash_init(uint8_t* data, uint32_t len, uint8_t* digest) {
    ISHAContext ctx;
    int err, i;

    err = ISHAReset(&ctx, SHA256, NULL);
    if (err) {
        printf("ISHAReset error: %d\n", err);
        return;
    }

    for (i = 0; i < len; i += TEST_BLOCK_LEN) {
        err = ISHAInput(&ctx, data, TEST_BLOCK_LEN, i);
        if (err) {
            printf("ISHAInput error: %d\n", err);
            return;
        }
        data += TEST_BLOCK_LEN;
    }

    ISHAResult(&ctx, digest);
}

__global__ void ihash_update(uint8_t* olddata,
                             uint8_t* newdata,
                             uint32_t len,
                             uint8_t* digest) {
    ISHAContext ctx;
    int err, i;

    err = ISHAReset(&ctx, SHA256, digest);
    if (err) {
        printf("ISHAReset error: %d\n", err);
        return;
    }

    for (i = 0; i < len; i += TEST_BLOCK_LEN) {
        err = ISHAUpdate(&ctx, olddata, newdata, TEST_BLOCK_LEN, i);
        if (err) {
            printf("ISHAUpdate error: %d\n", err);
            return;
        }
        olddata += TEST_BLOCK_LEN;
        newdata += TEST_BLOCK_LEN;
    }

    ISHAResult(&ctx, digest);
}

int main(int argc, char const* argv[]) {
    int i;
    uint8_t blocks[TEST_BLOCK_COUNT * TEST_BLOCK_LEN];
    uint8_t* dev_blocks;
    uint8_t new_blocks[TEST_BLOCK_COUNT * TEST_BLOCK_LEN];
    uint8_t* dev_new_blocks;
    uint8_t digest[USHAMaxHashSize] = {0};
    uint8_t* dev_digest;

    for (i = 0; i < TEST_BLOCK_COUNT; i++) {
        memset(blocks + i * TEST_BLOCK_LEN, i + 1, TEST_BLOCK_LEN);
    }
    for (i = 0; i < TEST_BLOCK_COUNT; i++) {
        memset(blocks + i * TEST_BLOCK_LEN, TEST_BLOCK_LEN - i, TEST_BLOCK_LEN);
    }

    cudaMalloc((void**)&dev_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN);
    cudaMalloc((void**)&dev_new_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN);
    cudaMalloc((void**)&dev_digest, USHAMaxHashSize);
    cudaMemcpy(dev_blocks, blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN,
               cudaMemcpyHostToDevice);
    cudaMemcpy(dev_new_blocks, new_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN,
               cudaMemcpyHostToDevice);
    cudaMemcpy(dev_digest, digest, USHAMaxHashSize, cudaMemcpyHostToDevice);

    // one aes_block per thread
    dim3 dimBlock(32, 1);
    // one xts_sector per block
    dim3 dimGrid(1, 1);

    ihash_init<<<dimGrid, dimBlock>>>(
        dev_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, dev_digest);
    cudaMemcpy(digest, dev_digest, USHAMaxHashSize, cudaMemcpyDeviceToHost);
    printf(
        "initial    :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
        "%.2x %.2x %.2x %.2x %.2x\n",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
        digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
        digest[12], digest[13], digest[14], digest[15]);

    cudaMemcpy(dev_blocks, blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN,
               cudaMemcpyHostToDevice);
    ihash_update<<<dimGrid, dimBlock>>>(dev_blocks, dev_new_blocks,
                                        TEST_BLOCK_COUNT * TEST_BLOCK_LEN,
                                        dev_digest);
    cudaMemcpy(digest, dev_digest, USHAMaxHashSize, cudaMemcpyDeviceToHost);
    printf(
        "updated    :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
        "%.2x %.2x %.2x %.2x %.2x\n",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
        digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
        digest[12], digest[13], digest[14], digest[15]);

    ihash_init<<<dimGrid, dimBlock>>>(
        dev_new_blocks, TEST_BLOCK_COUNT * TEST_BLOCK_LEN, dev_digest);
    cudaMemcpy(digest, dev_digest, USHAMaxHashSize, cudaMemcpyDeviceToHost);
    printf(
        "onepass    :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
        "%.2x %.2x %.2x %.2x %.2x\n",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
        digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
        digest[12], digest[13], digest[14], digest[15]);

    return 0;
}

#endif