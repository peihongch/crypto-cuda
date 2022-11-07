#define GXTS_HMAC

#include "gaes_xts.cu"
#include "hash/sha.h"

#define CIPHER_KEY_LENGTH (128)  // 128B or 1024b
#define AES_KEY_LENGTH (64)      // 64B or 512b
#define HMAC_KEY_LENGTH (64)     // 64B or 512b
#define MAC_LENGTH (64)          // 64B or 512b

__device__ void hmac_sha(const unsigned char* text,
                         int text_len,
                         const unsigned char* aad,
                         int aad_len,
                         const unsigned char* key,
                         int key_len,
                         uint8_t digest[USHAMaxHashSize]) {
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
__global__ void xts_hmac_encrypt(uint8_t* key,
                                 uint32_t key_len,
                                 uint8_t* data,
                                 const uint64_t tweak,
                                 uint8_t* mac) {
    xts_encrypt(key, key_len, data, tweak);

    if (threadIdx.x % 32 == 0) {
        uint64_t aad[2] = {tweak + blockIdx.x, 0};
        uint8_t* data_block = data + XTS_SECTOR_SIZE * blockIdx.x;
        hmac_sha(key + AES_KEY_LENGTH, HMAC_KEY_LENGTH, (unsigned char*)aad,
                 sizeof(aad), data_block, XTS_SECTOR_SIZE,
                 mac + MAC_LENGTH * blockIdx.x);
    }
}

__global__ void xts_hmac_decrypt(uint8_t* key,
                                 uint32_t key_len,
                                 uint8_t* data,
                                 const uint64_t tweak,
                                 uint8_t* mac) {
    if (threadIdx.x % 32 == 0) {
        uint64_t aad[2] = {tweak + blockIdx.x, 0};
        uint8_t* data_block = data + XTS_SECTOR_SIZE * blockIdx.x;
        hmac_sha(key + AES_KEY_LENGTH, HMAC_KEY_LENGTH, (unsigned char*)aad,
                 sizeof(aad), data_block, XTS_SECTOR_SIZE,
                 mac + MAC_LENGTH * blockIdx.x);
    }

    xts_decrypt(key, key_len, data, tweak);
}

#define TEXT_SIZE (4 * 1024 * 1024)
#define KEY_LENGTH (64)

int main(int argc, char const* argv[]) {
    uint8_t* dev_text;
    uint8_t* text = (uint8_t*)malloc(TEXT_SIZE);
    uint8_t* dev_mac;
    uint8_t* mac[MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE)] = {0};
    uint8_t* dev_key;
    uint8_t key[KEY_LENGTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

    uint32_t key_bit[3] = {128, 192, 256};
    memset(text, 1, TEXT_SIZE);

    cudaMalloc((void**)&dev_text, TEXT_SIZE);
    cudaMalloc((void**)&dev_mac, MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE));
    cudaMalloc((void**)&dev_key, sizeof(key));
    cudaMemcpy(dev_text, text, TEXT_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_key, key, sizeof(key), cudaMemcpyHostToDevice);

    // one aes_block per thread
    dim3 dimBlock(XTS_SECTOR_SIZE / AES_BLOCK_SIZE, 1);
    // one xts_sector per block
    dim3 dimGrid(TEXT_SIZE / XTS_SECTOR_SIZE, 1);

    uint32_t i;
    for (i = 0; i < sizeof(key_bit) / sizeof(key_bit[0]); ++i) {
        printf("key_bit %d: \n", key_bit[i]);
        printf(
            "\tinput    :   0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x "
            "0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6],
            text[7], text[8], text[9], text[10], text[11], text[12], text[13],
            text[14], text[15]);

        xts_hmac_encrypt<<<dimGrid, dimBlock>>>(dev_key, key_bit[i] * 2 / 8,
                                                dev_text, 0, dev_mac);
        cudaMemcpy(text, dev_text, TEXT_SIZE, cudaMemcpyDeviceToHost);
        cudaMemcpy(mac, dev_mac, MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE),
                   cudaMemcpyDeviceToHost);
        printf(
            "\tencrypt  :   0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x "
            "0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6],
            text[7], text[8], text[9], text[10], text[11], text[12], text[13],
            text[14], text[15]);
        printf(
            "\t└──mac   :   0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x "
            "0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7],
            mac[8], mac[9], mac[10], mac[11], mac[12], mac[13], mac[14],
            mac[15]);

        xts_hmac_decrypt<<<dimGrid, dimBlock>>>(dev_key, key_bit[i] * 2 / 8,
                                                dev_text, 0, dev_mac);
        cudaMemcpy(text, dev_text, TEXT_SIZE, cudaMemcpyDeviceToHost);
        cudaMemcpy(mac, dev_mac, MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE),
                   cudaMemcpyDeviceToHost);
        printf(
            "\tdecrypt  :   0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x "
            "0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6],
            text[7], text[8], text[9], text[10], text[11], text[12], text[13],
            text[14], text[15]);
        printf(
            "\t└──mac   :   0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x "
            "0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7],
            mac[8], mac[9], mac[10], mac[11], mac[12], mac[13], mac[14],
            mac[15]);
    }
    return 0;
}
