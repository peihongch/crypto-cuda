#include "hash/xts.cuh"
#include "hash/aes.cuh"

#include <vector>
#include <cstdio>

using namespace cuda;

#define TEXT_SIZE (4 * 1024 * 1024)
#define KEY_LENGTH (AES_KEY_LENGTH + HMAC_KEY_LENGTH)  // 128B or 1024b

int main(int argc, char const* argv[])
{
    uint8_t* dev_text = nullptr;
    std::vector<uint8_t> text(TEXT_SIZE, 1);
    uint8_t* dev_mac = nullptr;
    uint8_t mac[MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE)] = {0};
    uint8_t* dev_key = nullptr;
    uint8_t key[KEY_LENGTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    };

    cudaMalloc((void**) &dev_text, TEXT_SIZE);
    cudaMalloc((void**) &dev_mac, MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE));
    cudaMalloc((void**) &dev_key, sizeof(key));
    cudaMemcpy(dev_text, text.data(), TEXT_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(dev_key, key, sizeof(key), cudaMemcpyHostToDevice);

    // one aes_block per thread
    dim3 dimBlock(XTS_SECTOR_SIZE / AES_BLOCK_SIZE, 1);
    // one xts_sector per block
    dim3 dimGrid(TEXT_SIZE / XTS_SECTOR_SIZE, 1);

    printf("input    :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6], text[7],
            text[8], text[9], text[10], text[11], text[12], text[13], text[14], text[15]);

    xts_hmac_encrypt<<<dimGrid, dimBlock>>>(dev_key, KEY_LENGTH, dev_text, 0, dev_mac);
    cudaMemcpy(text.data(), dev_text, TEXT_SIZE, cudaMemcpyDeviceToHost);
    cudaMemcpy(mac, dev_mac, MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE), cudaMemcpyDeviceToHost);
    printf("encrypt  :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
            text[0], text[1], text[2], text[3], text[4], text[5], text[6], text[7],
            text[8], text[9], text[10], text[11], text[12], text[13], text[14], text[15]);
    printf("\tmac  :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7], mac[8],
            mac[9], mac[10], mac[11], mac[12], mac[13], mac[14], mac[15], mac[16],
            mac[17], mac[18], mac[19], mac[20], mac[21], mac[22], mac[23], mac[24],
            mac[25], mac[26], mac[27], mac[28], mac[29], mac[30], mac[31]);

    xts_hmac_decrypt<<<dimGrid, dimBlock>>>(dev_key, KEY_LENGTH, dev_text, 0, dev_mac);
    cudaMemcpy(text.data(), dev_text, TEXT_SIZE, cudaMemcpyDeviceToHost);
    cudaMemcpy(mac, dev_mac, MAC_LENGTH * (TEXT_SIZE / XTS_SECTOR_SIZE), cudaMemcpyDeviceToHost);
    printf("decrypt  :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
           text[0], text[1], text[2], text[3], text[4], text[5], text[6], text[7],
           text[8], text[9], text[10], text[11], text[12], text[13], text[14], text[15]);
    printf("\tmac  :   %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7], mac[8],
            mac[9], mac[10], mac[11], mac[12], mac[13], mac[14], mac[15], mac[16],
            mac[17], mac[18], mac[19], mac[20], mac[21], mac[22], mac[23], mac[24],
            mac[25], mac[26], mac[27], mac[28], mac[29], mac[30], mac[31]);

    return 0;
}
