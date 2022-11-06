#define GXTS_HMAC

#include "gaes_xts.cu"
#include "ghmac_sha.cu"

#define CIPHER_KEY_LENGTH (128)  // 128B or 1024b
#define AES_KEY_LENGTH (64)      // 64B or 512b
#define HMAC_KEY_LENGTH (64)     // 64B or 512b
#define MAC_LENGTH (64)          // 64B or 512b

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
                                 uint8_t mac[MAC_LENGTH]) {

}

int main(int argc, char const* argv[]) {
    return 0;
}
