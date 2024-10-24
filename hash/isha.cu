/*
 *  Description:
 *     This file implements an incremental hash function based on the SHA
 * algorithms.
 */

#include "sha.h"

#include <cstdio>

namespace cuda
{
    __device__ int ISHAReset(ISHAContext* ctx, SHAversion whichSha, uint8_t state[USHAMaxHashSize])
    {
        if (ctx)
        {
            ctx->whichSha = whichSha;
            if (state)
            {
                ctx->state = state;
            }
            else
            {
                ctx->state = ctx->intermediate_hash;
                for (uint32_t i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x)
                {
                    ctx->state[i] = 0;
                }
            }
            return USHAReset(&ctx->shaContext, whichSha);
        }
        else
        {
            return shaNull;
        }
    }

    __device__ int ISHAInput(ISHAContext* ctx, const uint8_t* bytes, unsigned int bytecount, const uint32_t index)
    {
        int err;
        if (ctx)
        {
            // tmp = Hash(data || ID)
            err = USHAReset(&ctx->shaContext, ctx->whichSha) ||
                  USHAInput(&ctx->shaContext, bytes, bytecount) ||
                  USHAInput(&ctx->shaContext, (uint8_t*) &index, sizeof(index)) ||
                  USHAResult(&ctx->shaContext, ctx->tmp);
            if (err)
            {
                return err;
            }

            // h = h XOR tmp
            // for (i = 0; i < USHAMaxHashSize; i++) {
            //     ctx->state[i] ^= ctx->tmp[i];
            // }
            // FIXME: how to make it more general?
            for (uint32_t i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x)
            {
                ctx->state[i] ^= ctx->tmp[i];
            }
            return shaSuccess;
        }
        else
        {
            return shaNull;
        }
    }

    __device__ int ISHAUpdate(ISHAContext* ctx, const uint8_t* oldbytes, const uint8_t* newbytes, unsigned int bytecount, const uint32_t index)
    {
        if (ctx)
        {
            // h = h XOR Hash(olddata || ID)
            // XOR Hash(newdata || ID) into state
            return ISHAInput(ctx, oldbytes, bytecount, index) ||
                   // XOR Hash(newdata || ID) into state
                   ISHAInput(ctx, newbytes, bytecount, index);
        }
        else
        {
            return shaNull;
        }
    }

    __device__ int ISHAResult(ISHAContext* ctx, uint8_t Message_Digest[USHAMaxHashSize])
    {
        if (ctx)
        {
            for (uint32_t i = threadIdx.x; i < USHAMaxHashSize; i += blockDim.x)
            {
                Message_Digest[i] = ctx->state[i];
            }
            return shaSuccess;
        }
        else
        {
            return shaNull;
        }
    }

    __global__ void IHASHInit(const SHAversion whichSha, const uint32_t blockLength, const uint8_t* data, const uint32_t len, uint8_t* digest)
    {
        ISHAContext ctx;

        int err = ISHAReset(&ctx, whichSha, nullptr);
        if (err)
        {
            printf("ISHAReset error: %d\n", err);
            return;
        }

        for (uint32_t i = 0; i < len; i += blockLength)
        {
            err = ISHAInput(&ctx, data, blockLength, i);
            if (err)
            {
                printf("ISHAInput error: %d\n", err);
                return;
            }
            data += blockLength;
        }

        ISHAResult(&ctx, digest);
    }

    __global__ void IHASHUpdate(const SHAversion whichSha, const uint32_t blockLength, uint8_t* olddata, uint8_t* newdata, const uint32_t len, uint8_t* digest)
    {
        ISHAContext ctx;
        int err = ISHAReset(&ctx, whichSha, digest);
        if (err)
        {
            printf("ISHAReset error: %d\n", err);
            return;
        }

        for (uint32_t i = 0; i < len; i += blockLength)
        {
            err = ISHAUpdate(&ctx, olddata, newdata, blockLength, i);
            if (err)
            {
                printf("ISHAUpdate error: %d\n", err);
                return;
            }
            olddata += blockLength;
            newdata += blockLength;
        }

        ISHAResult(&ctx, digest);
    }
}