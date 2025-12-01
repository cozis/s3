#ifndef S3_INCLUDED
#define S3_INCLUDED

#include <time.h>

#define S3_S(X) (S3_String) { (X), sizeof(X)-1 }

enum {
    S3_OUT_OF_MEMORY = -1,
    S3_LIB_ERROR     = -2,
};

typedef struct {
    char *ptr;
    int   len;
} S3_String;

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
    char *dst,
    int   cap);

#endif // S3_INCLUDED
