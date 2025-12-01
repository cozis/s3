#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/params.h>

#include "s3.h"

#ifdef NDEBUG
#define UNREACHABLE
#else
#define UNREACHABLE __builtin_trap()
#endif

// If the URL is not being created correctly,
// uncomment this do dump the state of the
// builder at each step:
//
//   #define TRACE_BUILDER

#ifndef PREALLOC_CAPACITY
#define PREALLOC_CAPACITY (1<<10)
#endif

//////////////////////////////////////////////////////////////////
// ENCODERS
//////////////////////////////////////////////////////////////////

static int hex_len(char *str, int len)
{
    (void) str;
    return 2 * len;
}

static int inplace_hex(char *buf, int len, bool up)
{
    int olen = hex_len(buf, len);
    if (olen == 0)
        return 0;

    int rlen = len;
    int wlen = olen;

    static const char uptable[] = "0123456789ABCDEF";
    static const char lotable[] = "0123456789abcdef";

    while (rlen > 0) {
        uint8_t b = (uint8_t) buf[--rlen];
        buf[--wlen] = (up ? uptable : lotable)[b & 0xF];
        buf[--wlen] = (up ? uptable : lotable)[b >> 4];
    }
    assert(rlen == 0);
    assert(wlen == 0);

    return 0;
}

// TODO: double check this function
static bool needs_percent(char c)
{
    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        (c == '-' || c == '_' || c == '.' || c == '~'))
        return false;
    return true;
}

static int pct_len(char *str, int len)
{
    int olen = 0;
    for (int i = 0; i < len; i++) {
        if (needs_percent(str[i]))
            olen += 3;
        else
            olen++;
    }
    return olen;
}

static int inplace_pct(char *buf, int len, bool up)
{
    int olen = pct_len(buf, len);
    if (olen == 0)
        return 0;

    int ridx = len;
    int widx = olen;

    static const char uptable[] = "0123456789ABCDEF";
    static const char lotable[] = "0123456789abcdef";

    while (ridx > 0) {
        char c = buf[--ridx];
        if (needs_percent(c)) {
            uint8_t b = c;
            buf[--widx] = (up ? uptable : lotable)[b & 0xF];
            buf[--widx] = (up ? uptable : lotable)[b >> 4];
            buf[--widx] = '%';
        } else {
            buf[--widx] = c;
        }
    }
    assert(ridx == 0);
    assert(widx == 0);

    return 0;
}

static int sha256_len(char *buf, int len)
{
    (void) buf;
    (void) len;
    return 32;
}

// src and dst may overlap
static int sha256(char *src, int len, char *dst)
{
    int olen = sha256_len(src, len);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, src, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, (unsigned char*) dst, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (hash_len != (unsigned int) olen) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

static int inplace_sha256(char *buf, int len)
{
    return sha256(buf, len, buf);
}

static int hmac_len(char *buf, int len1, int len2)
{
    (void) buf;
    (void) len1;
    (void) len2;
    return 32;
}

static int inplace_hmac(char *buf, int len1, int len2)
{
    int olen = hmac_len(buf, len1, len2);

    S3_String key = { buf, len1 };
    S3_String data = { buf + len1, len2 };

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return -1;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(ctx, (unsigned char*) key.ptr, key.len, params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    if (EVP_MAC_update(ctx, (unsigned char*) data.ptr, data.len) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    size_t mac_len;
    if (EVP_MAC_final(ctx, (unsigned char*) buf, &mac_len, EVP_MAX_MD_SIZE) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }
    if (mac_len != (size_t) olen) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -1;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return olen;
}

//////////////////////////////////////////////////////////////////
// BUILDER
//////////////////////////////////////////////////////////////////

#define MAX_MODIFIERS 32

typedef enum {
    MOD_HEX,
    MOD_PCT,
    MOD_SHA256,
    MOD_HMAC,
} ModifierType;

typedef struct {
    ModifierType type;
    int off_0;
    int off_1;
} Modifier;

typedef struct {
    char *dst;
    int   cap;
    int   len;
    Modifier mods[MAX_MODIFIERS];
    int num_mods;
    int status;
} Builder;

void builder_init(Builder *b, char *dst, int cap)
{
    b->dst = dst;
    b->cap = cap;
    b->len = 0;
    b->num_mods = 0;
    b->status = 0;
}

#ifdef TRACE_BUILDER
static void dump(Builder *builder, char *file, int line)
{
    printf("%s:%d\n", file, line);
    switch (builder->status) {
    case 0:
        printf("  status=OK\n");
        break;
    case S3_OUT_OF_MEMORY:
        printf("  status=OUT_OF_MEMORY\n");
        break;
    case S3_LIB_ERROR:
        printf("  status=LIB_ERROR\n");
        break;
    }
    printf("  len=%d\n", builder->len);
    printf("  dst=[\n    ");
    for (int i = 0; i < builder->len; i++) {
        if (i % 32 == 0)
            printf("\n    ");
        if (i < builder->cap) {
            char c = builder->dst[i];
            if ((uint8_t) c < 32 || (uint8_t) c > 127)
                putc('.', stdout);
            else
                putc(c, stdout);
        } else {
            putc('-', stdout);
        }
    }
    printf("\n  ]\n");
    printf("\n");
}
#endif

static void append_(Builder *b, S3_String s, char *file, int line)
{
    if (b->status == 0) {
        if (b->cap - b->len < s.len) {
            b->status = S3_OUT_OF_MEMORY;
        } else {
            memcpy(b->dst + b->len, s.ptr, s.len);
        }
    }
    b->len += s.len;

#ifdef TRACE_BUILDER
    dump(b, file, line);
#else
    (void) file;
    (void) line;
#endif
}

static void push_mod(Builder *b, ModifierType m)
{
    assert(b->num_mods < MAX_MODIFIERS);

    b->mods[b->num_mods].type = m;
    b->mods[b->num_mods].off_0 = b->len;
    b->mods[b->num_mods].off_1 = -1;
    b->num_mods++;
}

static void flush(Builder *b)
{
    if (b->status != 0)
        return;

    assert(b->num_mods > 0);
    assert(b->mods[b->num_mods-1].type == MOD_HMAC);
    assert(b->mods[b->num_mods-1].off_1 == -1);

    b->mods[b->num_mods-1].off_1 = b->len;
}

static void pop_mod_(Builder *b, char *file, int line)
{
    assert(b->num_mods > 0);
    Modifier mod = b->mods[--b->num_mods];

    int olen;
    switch (mod.type) {
    case MOD_HEX:
        olen = hex_len(
            b->dst + mod.off_0,
            b->len - mod.off_0);
        break;
    case MOD_PCT:
        olen = pct_len(
            b->dst + mod.off_0,
            b->len - mod.off_0);
        break;
    case MOD_SHA256:
        olen = sha256_len(
            b->dst + mod.off_0,
            b->len - mod.off_0);
        break;
    case MOD_HMAC:
        olen = hmac_len(
            b->dst + mod.off_0,
            mod.off_1 - mod.off_0,
            b->len - mod.off_1);
        break;
    }

    if (olen > b->cap - mod.off_0
        && b->status == 0)
        b->status = S3_OUT_OF_MEMORY;

    if (b->status == 0) {

        int ret;
        switch (mod.type) {
        case MOD_HEX:
            ret = inplace_hex(
                b->dst + mod.off_0,
                b->len - mod.off_0,
                true);
            break;
        case MOD_PCT:
            ret = inplace_pct(
                b->dst + mod.off_0,
                b->len - mod.off_0,
                true);
            break;
        case MOD_SHA256:
            ret = inplace_sha256(
                b->dst + mod.off_0,
                b->len - mod.off_0);
            break;
        case MOD_HMAC:
            ret = inplace_hmac(
                b->dst + mod.off_0,
                mod.off_1 - mod.off_0,
                b->len - mod.off_1);
            break;
        }

        if (ret < 0)
            b->status = S3_LIB_ERROR;
    }

    b->len = mod.off_0 + olen;

#ifdef TRACE_BUILDER
    dump(b, file, line);
#else
    (void) file;
    (void) line;
#endif
}

#ifdef TRACE_BUILDER
#define append(b, s) append_(b, s, __FILE__, __LINE__)
#define pop_mod(b) pop_mod_(b, __FILE__, __LINE__)
#else
#define append(b, s) append_(b, s, NULL, 0)
#define pop_mod(b) pop_mod_(b, NULL, 0)
#endif

//////////////////////////////////////////////////////////////////
// PRESIGN FUNCTION
//////////////////////////////////////////////////////////////////

static void append_credential(Builder *b,
    S3_String access_key, S3_String yyyymmdd,
    S3_String region, S3_String service)
{
    append(b, access_key);
    append(b, S3_S("/"));
    append(b, yyyymmdd);
    append(b, S3_S("/"));
    append(b, region);
    append(b, S3_S("/"));
    append(b, service);
    append(b, S3_S("/aws4_request"));
}

static int unpack_time(time_t time, struct tm *out)
{
#ifdef _WIN32
    if (gmtime_s(out, time) != 0)
        return -1;
    return 0;
#else
    if (gmtime_r(&time, out) == NULL)
        return -1;
    return 0;
#endif
}

int s3_presign_url(
    S3_String bucket,
    S3_String object,
    S3_String method,
    int       expire,
    S3_String payload,
    S3_String access_key,
    S3_String secret_access_key,
    S3_String region,
    S3_String service,
    S3_String host,
    time_t    now,
    char*     dst,
    int       cap)
{
    char prealloc[PREALLOC_CAPACITY];

    char *pool = prealloc;
    int   pool_cap = (int) sizeof(prealloc);

    struct tm unpacked_now;
    if (unpack_time(now, &unpacked_now))
        return -1; // TODO

    char date_buf_0[sizeof("YYYYMMDD")];
    char date_buf_1[sizeof("YYYYMMDDthhmmssz")];

    int ret = strftime(date_buf_0, sizeof(date_buf_0),
        "%Y%m%d", &unpacked_now);
    if (ret != sizeof(date_buf_0)-1)
        return -1; // TODO
    S3_String yyyymmdd = {
        date_buf_0,
        sizeof(date_buf_0)-1
    };

    ret = strftime(date_buf_1, sizeof(date_buf_1),
        "%Y%m%dT%H%M%SZ", &unpacked_now);
    if (ret != sizeof(date_buf_1)-1)
        return -1; // TODO
    S3_String yyyymmddthhmmssz = {
        date_buf_1,
        sizeof(date_buf_1)-1
    };

    char hash_buf[32];
    if (payload.len > 0) {
        if (sha256(payload.ptr, payload.len, hash_buf) < 0)
            return -1;
    }
    S3_String hash = { hash_buf, sizeof(hash_buf) };

    char expire_buf[11];
    ret = snprintf(expire_buf, sizeof(expire_buf), "%d", expire);
    if (ret < 0 || ret >= (int) sizeof(expire_buf))
        return -1;
    S3_String expire_str = { expire_buf, ret };

    for (int i = 0; i < 2; i++) {

        Builder b;
        builder_init(&b, pool, pool_cap);
        append(&b, S3_S("https://"));
        append(&b, host);
        append(&b, S3_S("/"));
        push_mod(&b, MOD_PCT);
            append(&b, bucket);
        pop_mod(&b);
        append(&b, S3_S("/"));
        push_mod(&b, MOD_PCT);
            append(&b, object);
        pop_mod(&b);
        append(&b, S3_S("?X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        append(&b, S3_S("&X-Amz-Credential="));
        push_mod(&b, MOD_PCT);
            append_credential(&b, access_key, yyyymmdd, region, service);
        pop_mod(&b);
        append(&b, S3_S("&X-Amz-Date="));
        append(&b, yyyymmddthhmmssz);
        append(&b, S3_S("&X-Amz-Expires="));
        append(&b, expire_str);
        append(&b, S3_S("&X-Amz-SignedHeaders=host"));
        append(&b, S3_S("&X-Amz-Signature="));
        push_mod(&b, MOD_HEX);
            push_mod(&b, MOD_HMAC);
                push_mod(&b, MOD_HMAC);
                    push_mod(&b, MOD_HMAC);
                        push_mod(&b, MOD_HMAC);
                            push_mod(&b, MOD_HMAC);
                                append(&b, S3_S("AWS4"));
                                append(&b, secret_access_key);
                                flush(&b);
                                append(&b, yyyymmdd);
                            pop_mod(&b);
                            flush(&b);
                            append(&b, region);
                        pop_mod(&b);
                        flush(&b);
                        append(&b, service);
                    pop_mod(&b);
                    flush(&b);
                    append(&b, S3_S("aws4_request"));
                pop_mod(&b);
                flush(&b);
                push_mod(&b, MOD_HEX);
                    push_mod(&b, MOD_SHA256);
                        append(&b, method);
                        append(&b, S3_S("\n"));
                        append(&b, S3_S("/"));
                        push_mod(&b, MOD_PCT);
                            append(&b, bucket);
                        pop_mod(&b);
                        append(&b, S3_S("/"));
                        push_mod(&b, MOD_PCT);
                            append(&b, object);
                        pop_mod(&b);
                        append(&b, S3_S("\n"));
                        append(&b, S3_S("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
                        append(&b, S3_S("&X-Amz-Credential="));
                        push_mod(&b, MOD_PCT);
                            append_credential(&b, access_key, yyyymmdd, region, service);
                        pop_mod(&b);
                        append(&b, S3_S("&X-Amz-Date="));
                        append(&b, yyyymmddthhmmssz);
                        append(&b, S3_S("&X-Amz-Expires="));
                        append(&b, expire_str);
                        append(&b, S3_S("&X-Amz-SignedHeaders=host\n"));
                        append(&b, S3_S("host:"));
                        append(&b, host);
                        append(&b, S3_S("\n"));
                        append(&b, S3_S("\n"));
                        append(&b, S3_S("host\n"));
                        if (payload.len == 0) {
                        append(&b, S3_S("UNSIGNED-PAYLOAD"));
                        } else {
                        push_mod(&b, MOD_HEX);
                            append(&b, hash);
                        pop_mod(&b);
                        }
                    pop_mod(&b);
                pop_mod(&b);
            pop_mod(&b);
        pop_mod(&b);

        switch (b.status) {

        case 0:
            if (b.len > cap) {
                // The presigned URL was built correctly, but it
                // won't fit inside the user-provided buffer.
                //
                // Nothing we can do here other than fail!
                if (i == 1) free(pool);
                return S3_OUT_OF_MEMORY;
            }

            memcpy(dst, b.dst, b.len);
            if (i == 1) free(pool);
            return b.len;

        case S3_OUT_OF_MEMORY:
            // We failed to build the presigned URL because
            // our pool was too small. This should only happen
            // during the first attempt
            assert(i == 0);

            // Allocate a proper pool and try again
            pool_cap = b.len;
            pool = malloc(b.len);
            if (pool == NULL)
                return S3_OUT_OF_MEMORY;
            break;

        case S3_LIB_ERROR:
            // We failed due to a library error. Nothing we
            // can do here either.
            if (i == 1) free(pool);
            return S3_LIB_ERROR;

        default:
            UNREACHABLE;
            break;
        }
    }

    UNREACHABLE;
    return 0;
}
