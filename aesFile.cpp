#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
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
char passCode[256] = "hello";

typedef struct
{
    uint64_t fileSize;
    uint64_t dummy;
}   fileHeader_t;

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
    fprintf(stderr, "-O --OUTPUT filename    Output file (overwrite)\n");
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
    char filenameIn[256] = {0};
    char filenameOut[256] = {0};
    bool encryptFlag = false;
    bool decryptFlag = false;
    bool outputOverwrite = false;
    uint8_t *pBuf;               // The encryption and decryption is performed in-place
    fileHeader_t fileHeader;

    struct option longOptions[] =
    {
        {"input",           required_argument,  0,      'i'}
        ,{"output",         required_argument,  0,      'o'}
        ,{"OUTPUT",         required_argument,  0,      'O'}
        ,{"passcode",       required_argument,  0,      'p'}
        ,{"encrypt",        no_argument,        0,      'e'}
        ,{"decrypt",        no_argument,        0,      'd'}
        ,{"help",           no_argument,        0,      'h'}
        ,{0,0,0,0}
    };

    while (1)
    {
        int optionIndex = 0;

        opt = getopt_long(argc, argv, "i:o:O:p:edh?", longOptions, &optionIndex);

        if (-1 == opt)
            break;

        switch (opt)
        {
            case 'i':
                strlcpy(filenameIn, optarg, sizeof(filenameIn));
                break;
            case 'O':
                outputOverwrite = true;
                // Intentional fall-through
            case 'o':
                strlcpy(filenameOut, optarg, sizeof(filenameOut));
                break;
            case 'p':
                strlcpy(passCode, optarg, sizeof(passCode));
                break;
            case 'e':
                encryptFlag = true;
                break;
            case 'd':
                decryptFlag = true;
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

    if (0 == strlen(passCode))
    {
        usage(basename(argv[0]), "Must Enter a PassCode");
        return -1;
    }

    pBuf = (uint8_t *)(malloc(blocklen));

    if (!pBuf)
    {
        fprintf(stderr, "Error allocating buffer of size %ld\n", blocklen);
        return -1;
    }

    fpIn = fopen(filenameIn, "rb");
    if ((FILE *)(NULL) == fpIn)
    {
        fprintf(stderr, "Can't open input file %s\n", optarg);
        return -1;
    }

    if  (   (0 == access(filenameOut, F_OK))
         && (false == outputOverwrite)
        )
    {
        fprintf(stderr, "Output file %s exists.  Use -O to overwrite\n", filenameOut);
        closeFiles(fpIn);
        return -1;
    }

    fpOut = fopen(filenameOut, "wb");
    if ((FILE *)(NULL) == fpOut)
    {
        fprintf(stderr, "Can't open output file %s\n", optarg);
        closeFiles(fpIn);
        return -1;
    }

    // Generate AES key and IV from file hash.
    // This works because we know that our AES key is 16 bytes
    // and the initialization vector is 16 bytes
    // and the hash is 32 bytes.
    Csha256 theHash;
    uint8_t hashBytes[SHA256_BLOCK_SIZE];
    theHash.update((uint8_t *)passCode, strlen(passCode));
    theHash.final();
    theHash.getHash(hashBytes);
    // Use the first 16 bytes of the hash as the AES key
    // and the last 16 bytes of the hash as the IV
    memcpy(aesKey, hashBytes, AES_KEYLEN);
    memcpy(initializationVector, &hashBytes[AES_KEYLEN], AES_IV_LEN);

    #if 0
    char hashString[SHA256_BLOCK_SIZE * 2 + 1] = {0};
    theHash.getHashString(hashString);

    printf("Hash of passCode %s is\n%s\n"
        , passCode
        , hashString
        );
    #endif

    t1 = myclock();

    // Initialize the AES context structure with the key and the IV to be used
    AES_init_ctx_iv(&aesCtx1, aesKey, initializationVector);

    // The first 16 bytes of the encrypted file contain
    // the actual length of the unencrypted file
    if (encryptFlag)
    {
        fseek(fpIn, 0, SEEK_END);
        fileHeader.fileSize = (uint64_t)ftell(fpIn);
        rewind(fpIn);
        AES_CBC_encrypt_buffer(&aesCtx1, (uint8_t *)(&fileHeader), blocklen);
        fwrite(&fileHeader, sizeof(uint8_t), blocklen, fpOut);
    }
    else
    {
        n = fread(&fileHeader, sizeof(uint8_t), sizeof(fileHeader), fpIn);
        if (n != blocklen)
        {
            fprintf(stderr, "Error: File too short\n");
            closeFiles(fpIn);
            return -1;
        }
        AES_CBC_decrypt_buffer(&aesCtx1, (uint8_t *)(&fileHeader), blocklen);
        printf("Output file %ld bytes\n", fileHeader.fileSize);
    }

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
            n = blocklen;
        }
        else
        {
            AES_CBC_decrypt_buffer(&aesCtx1, pBuf, blocklen);
            if (fileHeader.fileSize < blocklen)
            {
                n = (size_t)fileHeader.fileSize;
            }
            fileHeader.fileSize -= (uint64_t)n;
        }
        fwrite(pBuf, sizeof(uint8_t), n, fpOut);
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
