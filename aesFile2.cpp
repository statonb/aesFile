#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <getopt.h>
#include "aes.h"
#include "randomBytes.h"
#include "strlcpy.h"
#include "csha256.h"

#define AES_IV_LEN          (16)
#define DEFAULT_BLOCK_LEN   (16)                // The size of the user data in the message must be a multiple of 16

uint8_t initializationVector[AES_IV_LEN] = {0x2D, 0x51, 0x8E, 0x1F, 0x56, 0x08, 0x57, 0x27, 0xA7, 0x05, 0xD4, 0xD0, 0x52, 0x82, 0x77, 0x75};
uint8_t aesKey[AES_KEYLEN] = {0xA3, 0x97, 0xA2, 0x55, 0x53, 0xBE, 0xF1, 0xFC, 0xF9, 0x79, 0x6B, 0x52, 0x14, 0x13, 0xE9, 0xE2};

long myclock()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000) + tv.tv_usec;
}

void printHex(const uint8_t *data, size_t n, const char *msg)
{
    size_t i;

    if (msg)
    {
        printf("%s(%ld)", msg, n);
    }
    for(i=0; i<n; i++)
    {
        if (0 == (i % 16))
        {
            printf("\n");
        }
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void usage(const char *prog, const char *extraLine = (const char *)(NULL));

void usage(const char *prog, const char *extraLine)
{
    fprintf(stderr, "usage: %s <options>\n", prog);
    fprintf(stderr, "-i --input  filename    Input file\n");
    fprintf(stderr, "-o --output filename    Output file\n");
    fprintf(stderr, "-e --encrypt            Encrypt\n");
    fprintf(stderr, "-d --decrypt            Decrypt\n");
    fprintf(stderr, "-s --seed   filename    Seed file\n");
    fprintf(stderr, "-n --blocklen  N        Block length.  Multiple of 16  Default = 16\n");
    if (extraLine)
        fprintf(stderr, "\n%s\n", extraLine);
}

void closeFiles(FILE *f1, FILE *f2 = (FILE *)(NULL));

void closeFiles(FILE *f1, FILE *f2)
{
    if ((FILE *)(NULL) != f1)
        fclose(f1);
    if ((FILE *)(NULL) != f2)
        fclose(f2);
}

int main(int argc, char *argv[])
{
    int opt;
    bool usageError = false;
    long t1, t2;
    size_t blocklen = DEFAULT_BLOCK_LEN;
    size_t n;
    struct AES_ctx aesCtx1;
    FILE *fpIn = (FILE *)(NULL);
    FILE *fpOut = (FILE *)(NULL);
    FILE *fpSeed = (FILE *)(NULL);
    char filenameIn[256] = {0};
    char filenameOut[256] = {0};
    char filenameSeed[256] = {0};
    char lineBuf[256];
    bool encryptFlag = false;
    bool decryptFlag = false;
    uint8_t *pBuf;               // The encryption and decryption is performed in-place

    struct option longOptions[] =
    {
        {"input",           required_argument,  0,      'i'}
        ,{"output",         required_argument,  0,      'o'}
        ,{"blocklen",       required_argument,  0,      'n'}
        ,{"seed",           required_argument,  0,      's'}
        ,{"encrypt",        no_argument,        0,      'e'}
        ,{"decrypt",        no_argument,        0,      'd'}
        ,{"help",           no_argument,        0,      'h'}
        ,{0,0,0,0}
    };

    while (1)
    {
        int optionIndex = 0;

        opt = getopt_long(argc, argv, "i:o:n:s:edh?", longOptions, &optionIndex);

        if (-1 == opt)
            break;

        switch (opt)
        {
            case 'i':
                strlcpy(filenameIn, optarg, sizeof(filenameIn));
                break;
            case 'o':
                strlcpy(filenameOut, optarg, sizeof(filenameOut));
                break;
            case 's':
                strlcpy(filenameSeed, optarg, sizeof(filenameSeed));
                break;
            case 'e':
                encryptFlag = true;
                decryptFlag = false;
                break;
            case 'd':
                encryptFlag = false;
                decryptFlag = true;
                break;
            case 'n':
                blocklen = (size_t)(strtoul(optarg, NULL, 10));
                if (0 != (blocklen % 16))
                {
                    fprintf(stderr, "Block length must be a multiple of 16\n");
                    return -1;
                }
                break;
            case 'h':
            case '?':
            default:
                usageError = true;
                break;
        }
    }

    if (usageError)
    {
        usage(basename(argv[0]));
        return -1;
    }

    if  (   (true == encryptFlag)
         && (true == decryptFlag)
        )
    {
        usage(basename(argv[0]), "Only Encrypt OR Decrypt");
        return -1;
    }

    if  (   (false == encryptFlag)
         && (false == decryptFlag)
        )
    {
        usage(basename(argv[0]), "Must Encrypt OR Decrypt");
        return -1;
    }

    pBuf = (uint8_t *)(malloc(blocklen));

    if (!pBuf)
    {
        fprintf(stderr, "Error allocating buffer of size %ld\n", blocklen);
        return -1;
    }

    if ('\0' != filenameSeed[0])
    {
        fpSeed = fopen(filenameSeed, "r");
        if ((FILE *)(NULL) == fpSeed)
        {
            fprintf(stderr, "Can't open seed file %s\n", optarg);
            return -1;
        }
    }

    fpIn = fopen(filenameIn, "rb");
    if ((FILE *)(NULL) == fpIn)
    {
        fprintf(stderr, "Can't open input file %s\n", optarg);
        closeFiles(fpSeed);
        return -1;
    }

    fpOut = fopen(filenameOut, "wb");
    if ((FILE *)(NULL) == fpOut)
    {
        fprintf(stderr, "Can't open output file %s\n", optarg);
        closeFiles(fpIn, fpSeed);
        return -1;
    }

    if ((FILE *)(NULL) != fpSeed)
    {
        // Generate AES key and IV from file hash.
        // This works because we know that our AES key is 16 bytes
        // and the initialization vector is 16 bytes
        // and the hash is 32 bytes.
        Csha256 theHash;
        uint8_t hashBytes[SHA256_BLOCK_SIZE];
        while (fgets(lineBuf, sizeof(lineBuf), fpSeed))
        {
            theHash.update((uint8_t *)lineBuf, strlen(lineBuf));
        }
        theHash.final();
        theHash.getHash(hashBytes);
        // Use the first 16 bytes of the hash as the AES key
        // and the last 16 bytes of the hash as the IV
        memcpy(aesKey, hashBytes, AES_KEYLEN);
        memcpy(initializationVector, &hashBytes[AES_KEYLEN], AES_IV_LEN);

        char hashString[SHA256_BLOCK_SIZE * 2 + 1] = {0};
        theHash.getHashString(hashString);

        printf("Hash of seed file %s is\n%s\n"
            , filenameSeed
            , hashString
            );
        fclose(fpSeed);
    }

    t1 = myclock();

    // Initialize the AES context structure with the key and the IV to be used
    AES_init_ctx_iv(&aesCtx1, aesKey, initializationVector);

    while ((n = fread(pBuf, sizeof(uint8_t), blocklen, fpIn)) > 0)
    {
        if (n < blocklen)
        {
            // zero pad the remainder of this buffer
            memset(&pBuf[n], 0, blocklen - n);
        }
        // Encrypt or Decrypt the message buffer in-place
        if (encryptFlag)
        {
            AES_CBC_encrypt_buffer(&aesCtx1, pBuf, blocklen);
        }
        else
        {
            AES_CBC_decrypt_buffer(&aesCtx1, pBuf, blocklen);
        }
        fwrite(pBuf, sizeof(uint8_t), blocklen, fpOut);
    }

    t2 = myclock();

    printf("%s time: %ld us\n"
        , (encryptFlag) ? "Encrypt" : "Decrypt"
        , (t2-t1)
        );

    closeFiles(fpIn, fpOut);
    free (pBuf);

    return 0;
}
