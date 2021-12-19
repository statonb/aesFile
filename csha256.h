#ifndef __CSHA256_H_
#define __CSHA256_H_

extern "C" {
#include "sha256.h"
}

class Csha256
{
    private:
        sha256_ctx_t  m_ctx;

    public:
        Csha256(void);

        void init(void);
        void update(const void *data, uint32_t len);
        void final(void);
        void getHash(uint8_t *hash);
        bool getHashString(char *hashString);

        void clearContext(void);
        bool isContextClear(void);
        bool isContextEqual(const sha256_ctx_t &x);

        friend bool operator==(const Csha256 &a, const Csha256 &b);
        friend bool operator!=(const Csha256 &a, const Csha256 &b);
};

bool operator==(const sha256_ctx_t &a, const sha256_ctx_t &b);
bool operator!=(const sha256_ctx_t &a, const sha256_ctx_t &b);

#endif
