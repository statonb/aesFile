#include "csha256.h"
#include <string.h>

Csha256::Csha256(void)
{
    init();
}

void Csha256::init(void)
{
    sha256_init(&m_ctx);
}

void Csha256::update(const void *data, uint32_t len)
{
    sha256_update(&m_ctx, data, len);
}

void Csha256::final(void)
{
    sha256_final(&m_ctx);
}

void Csha256::getHash(uint8_t *hash)
{
    sha256_getHash(&m_ctx, hash);
}

bool Csha256::getHashString(char *hashString)
{
    return sha256_getHashString(&m_ctx, hashString);
}

void Csha256::clearContext(void)
{
    sha256_clearContext(&m_ctx);
}

bool Csha256::isContextClear(void)
{
    {
        for (uint32_t i = 0; i < sizeof(m_ctx.d); i++)
        {
            if (m_ctx.d[i] != 0)
                return false;
        }
        return true;
    }
}

bool Csha256::isContextEqual(const sha256_ctx_t &x)
{
    return (m_ctx == x);
}

bool operator==(const Csha256 &a, const Csha256 &b)
{
    return (a.m_ctx == b.m_ctx);
}

bool operator!=(const Csha256 &a, const Csha256 &b)
{
    return !(a == b);
}


bool operator==(const sha256_ctx_t &a, const sha256_ctx_t &b)
{
    return (0 == memcmp(a.d, b.d, SHA256_BLOCK_SIZE)) ? true : false;
}

bool operator!=(const sha256_ctx_t &a, const sha256_ctx_t &b)
{
    return !(a == b);
}
