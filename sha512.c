// #include <cuda.h>
// #include <cuda_runtime.h>
#include "hash/sha-private.h"
#include "hash/sha.h"

/* Define the SHA shift, rotate left and rotate right macro */
#define SHA512_SHR(bits, word) (((uint64_t)(word)) >> (bits))
#define SHA512_ROTR(bits, word) \
    ((((uint64_t)(word)) >> (bits)) | (((uint64_t)(word)) << (64 - (bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA512_SIGMA0(word) \
    (SHA512_ROTR(28, word) ^ SHA512_ROTR(34, word) ^ SHA512_ROTR(39, word))
#define SHA512_SIGMA1(word) \
    (SHA512_ROTR(14, word) ^ SHA512_ROTR(18, word) ^ SHA512_ROTR(41, word))
#define SHA512_sigma0(word) \
    (SHA512_ROTR(1, word) ^ SHA512_ROTR(8, word) ^ SHA512_SHR(7, word))
#define SHA512_sigma1(word) \
    (SHA512_ROTR(19, word) ^ SHA512_ROTR(61, word) ^ SHA512_SHR(6, word))

/*
 * add "length" to the length
 */
#define SHA512AddLength(Length_Arr, length)                                \
    (addTemp = (Length_Arr)[0],                                            \
     (((Length_Arr)[0] += length) < addTemp) && ((Length_Arr)[1] == 0) ? 1 \
                                                                       : 0)

static void SHA512ProcessMessageBlock(uint8_t* Message_Block,
                                      uint64_t* Intermediate_Hash);

/* Initial Hash Values: FIPS-180-2 sections 5.3.3 and 5.3.4 */
static uint64_t SHA512_H0[] = {0x6A09E667F3BCC908ll, 0xBB67AE8584CAA73Bll,
                               0x3C6EF372FE94F82Bll, 0xA54FF53A5F1D36F1ll,
                               0x510E527FADE682D1ll, 0x9B05688C2B3E6C1Fll,
                               0x1F83D9ABFB41BD6Bll, 0x5BE0CD19137E2179ll};

/*
 * SHA512Hash
 *
 * Description:
 *   This function accepts an array of octets as the message.
 *
 * Parameters:
 *   message_array: [in]
 *     An array of characters representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array, must be a multiple of 8
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 * *
 */
int SHA512Hash(const uint8_t* message_array,
               unsigned int length,
               uint8_t Message_Digest[SHA512HashSize]) {
    int_least16_t Message_Block_Index = 0; /* Message_Block array index */
                                           /* 1024-bit message blocks */
    uint8_t Message_Block[SHA512_Message_Block_Size];
    int_least16_t i;
    int j;
    uint64_t addTemp;
    uint64_t Intermediate_Hash[SHA512HashSize / 8]; /* Message Digest */
    uint64_t Length[2] = {0, 0};                    /* Message length in bits */
    for (j = 0; j < SHA512HashSize / 8; j++)
        Intermediate_Hash[j] = SHA512_H0[j];

    while (length--) {
        Message_Block[Message_Block_Index++] = (*message_array & 0xFF);

        if (!SHA512AddLength(Length, 8) &&
            (Message_Block_Index == SHA512_Message_Block_Size)) {
            SHA512ProcessMessageBlock(Message_Block, Intermediate_Hash);
            Message_Block_Index = 0;
        }

        message_array++;
    }

    /*
     * Check to see if the current message block is too small to hold
     * the initial padding bits and length. If so, we will pad the
     * block, process it, and then continue padding into a second
     * block.
     */
    if (Message_Block_Index >= (SHA512_Message_Block_Size - 16)) {
        Message_Block[Message_Block_Index++] = 0x80;
        while (Message_Block_Index < SHA512_Message_Block_Size)
            Message_Block[Message_Block_Index++] = 0;
        SHA512ProcessMessageBlock(Message_Block, Intermediate_Hash);
    } else
        Message_Block[Message_Block_Index++] = 0x80;

    while (Message_Block_Index < (SHA512_Message_Block_Size - 16))
        Message_Block[Message_Block_Index++] = 0;

    /*
     * Store the message length as the last 16 octets
     */
    Message_Block[112] = (uint8_t)(Length[1] >> 56);
    Message_Block[113] = (uint8_t)(Length[1] >> 48);
    Message_Block[114] = (uint8_t)(Length[1] >> 40);
    Message_Block[115] = (uint8_t)(Length[1] >> 32);
    Message_Block[116] = (uint8_t)(Length[1] >> 24);
    Message_Block[117] = (uint8_t)(Length[1] >> 16);
    Message_Block[118] = (uint8_t)(Length[1] >> 8);
    Message_Block[119] = (uint8_t)(Length[1]);

    Message_Block[120] = (uint8_t)(Length[0] >> 56);
    Message_Block[121] = (uint8_t)(Length[0] >> 48);
    Message_Block[122] = (uint8_t)(Length[0] >> 40);
    Message_Block[123] = (uint8_t)(Length[0] >> 32);
    Message_Block[124] = (uint8_t)(Length[0] >> 24);
    Message_Block[125] = (uint8_t)(Length[0] >> 16);
    Message_Block[126] = (uint8_t)(Length[0] >> 8);
    Message_Block[127] = (uint8_t)(Length[0]);

    SHA512ProcessMessageBlock(Message_Block, Intermediate_Hash);

    for (i = 0; i < SHA512HashSize; ++i)
        Message_Digest[i] =
            (uint8_t)(Intermediate_Hash[i >> 3] >> 8 * (7 - (i % 8)));

    return shaSuccess;
}

/*
 * SHA512ProcessMessageBlock
 *
 * Description:
 *   This helper function will process the next 1024 bits of the
 *   message stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the publication.
 *
 *
 */
static void SHA512ProcessMessageBlock(
    uint8_t Message_Block[SHA512_Message_Block_Size],
    uint64_t Intermediate_Hash[SHA512_Message_Block_Size / 8]) {
    /* Constants defined in FIPS-180-2, section 4.2.3 */

    static const uint64_t K[80] = {
        0x428A2F98D728AE22ll, 0x7137449123EF65CDll, 0xB5C0FBCFEC4D3B2Fll,
        0xE9B5DBA58189DBBCll, 0x3956C25BF348B538ll, 0x59F111F1B605D019ll,
        0x923F82A4AF194F9Bll, 0xAB1C5ED5DA6D8118ll, 0xD807AA98A3030242ll,
        0x12835B0145706FBEll, 0x243185BE4EE4B28Cll, 0x550C7DC3D5FFB4E2ll,
        0x72BE5D74F27B896Fll, 0x80DEB1FE3B1696B1ll, 0x9BDC06A725C71235ll,
        0xC19BF174CF692694ll, 0xE49B69C19EF14AD2ll, 0xEFBE4786384F25E3ll,
        0x0FC19DC68B8CD5B5ll, 0x240CA1CC77AC9C65ll, 0x2DE92C6F592B0275ll,
        0x4A7484AA6EA6E483ll, 0x5CB0A9DCBD41FBD4ll, 0x76F988DA831153B5ll,
        0x983E5152EE66DFABll, 0xA831C66D2DB43210ll, 0xB00327C898FB213Fll,
        0xBF597FC7BEEF0EE4ll, 0xC6E00BF33DA88FC2ll, 0xD5A79147930AA725ll,
        0x06CA6351E003826Fll, 0x142929670A0E6E70ll, 0x27B70A8546D22FFCll,
        0x2E1B21385C26C926ll, 0x4D2C6DFC5AC42AEDll, 0x53380D139D95B3DFll,
        0x650A73548BAF63DEll, 0x766A0ABB3C77B2A8ll, 0x81C2C92E47EDAEE6ll,
        0x92722C851482353Bll, 0xA2BFE8A14CF10364ll, 0xA81A664BBC423001ll,
        0xC24B8B70D0F89791ll, 0xC76C51A30654BE30ll, 0xD192E819D6EF5218ll,
        0xD69906245565A910ll, 0xF40E35855771202All, 0x106AA07032BBD1B8ll,
        0x19A4C116B8D2D0C8ll, 0x1E376C085141AB53ll, 0x2748774CDF8EEB99ll,
        0x34B0BCB5E19B48A8ll, 0x391C0CB3C5C95A63ll, 0x4ED8AA4AE3418ACBll,
        0x5B9CCA4F7763E373ll, 0x682E6FF3D6B2B8A3ll, 0x748F82EE5DEFB2FCll,
        0x78A5636F43172F60ll, 0x84C87814A1F0AB72ll, 0x8CC702081A6439ECll,
        0x90BEFFFA23631E28ll, 0xA4506CEBDE82BDE9ll, 0xBEF9A3F7B2C67915ll,
        0xC67178F2E372532Bll, 0xCA273ECEEA26619Cll, 0xD186B8C721C0C207ll,
        0xEADA7DD6CDE0EB1Ell, 0xF57D4F7FEE6ED178ll, 0x06F067AA72176FBAll,
        0x0A637DC5A2C898A6ll, 0x113F9804BEF90DAEll, 0x1B710B35131C471Bll,
        0x28DB77F523047D84ll, 0x32CAAB7B40C72493ll, 0x3C9EBE0A15C9BEBCll,
        0x431D67C49C100D4Cll, 0x4CC5D4BECB3E42B6ll, 0x597F299CFC657E2All,
        0x5FCB6FAB3AD6FAECll, 0x6C44198C4A475817ll};
    int t, t8;                       /* Loop counter */
    uint64_t temp1, temp2;           /* Temporary word value */
    uint64_t W[80];                  /* Word sequence */
    uint64_t A, B, C, D, E, F, G, H; /* Word buffers */

    /*
     * Initialize the first 16 words in the array W
     */
    for (t = t8 = 0; t < 16; t++, t8 += 8)
        W[t] = ((uint64_t)(Message_Block[t8]) << 56) |
               ((uint64_t)(Message_Block[t8 + 1]) << 48) |
               ((uint64_t)(Message_Block[t8 + 2]) << 40) |
               ((uint64_t)(Message_Block[t8 + 3]) << 32) |
               ((uint64_t)(Message_Block[t8 + 4]) << 24) |
               ((uint64_t)(Message_Block[t8 + 5]) << 16) |
               ((uint64_t)(Message_Block[t8 + 6]) << 8) |
               ((uint64_t)(Message_Block[t8 + 7]));

    for (t = 16; t < 80; t++)
        W[t] = SHA512_sigma1(W[t - 2]) + W[t - 7] + SHA512_sigma0(W[t - 15]) +
               W[t - 16];

    A = Intermediate_Hash[0];
    B = Intermediate_Hash[1];
    C = Intermediate_Hash[2];
    D = Intermediate_Hash[3];
    E = Intermediate_Hash[4];
    F = Intermediate_Hash[5];
    G = Intermediate_Hash[6];
    H = Intermediate_Hash[7];

    for (t = 0; t < 80; t++) {
        temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
        temp2 = SHA512_SIGMA0(A) + SHA_Maj(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    Intermediate_Hash[0] += A;
    Intermediate_Hash[1] += B;
    Intermediate_Hash[2] += C;
    Intermediate_Hash[3] += D;
    Intermediate_Hash[4] += E;
    Intermediate_Hash[5] += F;
    Intermediate_Hash[6] += G;
    Intermediate_Hash[7] += H;
}

#include <stdio.h>

#define length(x) (sizeof(x) - 1)
#define TESTCOUNT 4

static const char hexdigits[] = "0123456789ABCDEF";

struct {
    const char* testarray;
    int length;
    const char* resultarray;
} tests[TESTCOUNT] = {
    {/* 1 */
     "abc", length("abc"),
     "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA2"
     "0A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD"
     "454D4423643CE80E2A9AC94FA54CA49F"},
    /* 2 */
    {"\xD0", 1,
     "9992202938E882E73E20F6B69E68A0A7149090423D93C81B"
     "AB3F21678D4ACEEEE50E4E8CAFADA4C85A54EA8306826C4A"
     "D6E74CECE9631BFA8A549B4AB3FBBA15"},
    /* 3 */
    {"\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0",
     length("\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0"),
     "CB0B67A4B8712CD73C9AABC0B199E9269B20844AFB75ACBD"
     "D1C153C9828924C3DDEDAAFE669C5FDD0BC66F630F677398"
     "8213EB1B16F517AD0DE4B2F0C95C90F8"},
    /* 4 */
    {"\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31"
     "\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde"
     "\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4"
     "\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2"
     "\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3"
     "\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95"
     "\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65"
     "\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f"
     "\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41"
     "\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28"
     "\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1"
     "\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8"
     "\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b"
     "\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7"
     "\xfb\x40\xd2",
     length("\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31"
            "\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde"
            "\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4"
            "\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2"
            "\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3"
            "\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95"
            "\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65"
            "\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f"
            "\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41"
            "\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28"
            "\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1"
            "\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8"
            "\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b"
            "\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7"
            "\xfb\x40\xd2"),
     "C665BEFB36DA189D78822D10528CBF3B12B3EEF726039909"
     "C1A16A270D48719377966B957A878E720584779A62825C18"
     "DA26415E49A7176A894E7510FD1451F5"}};

int main(int argc, char const* argv[]) {
    const char* test_array;
    int length;
    const char* result_array;
    uint8_t Message_Digest[SHA512HashSize];
    int i, j, k, res;

    for (j = 0; j < TESTCOUNT; j++) {
        test_array = tests[j].testarray;
        length = tests[j].length;
        result_array = tests[j].resultarray;
        printf("case %d: \n", j + 1);

        res = SHA512Hash((const uint8_t*)test_array, length, Message_Digest);
        if (res != shaSuccess) {
            printf("\tError: %d\n", res);
        } else {
            printf("\texpect: ");
            for (i = 0, k = 0; i < SHA512HashSize; i++, k += 2) {
                putchar(result_array[k]);
                putchar(result_array[k + 1]);
                putchar(' ');
            }
            putchar('\n');

            printf("\tactual: ");
            for (i = 0; i < SHA512HashSize; i++) {
                putchar(hexdigits[(Message_Digest[i] >> 4) & 0xF]);
                putchar(hexdigits[Message_Digest[i] & 0xF]);
                putchar(' ');
            }
            printf("\n");
        }
    }

    return 0;
}
