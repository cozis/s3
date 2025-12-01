#ifndef S3_INCLUDED
#define S3_INCLUDED

#include <time.h>

typedef struct {
    char *ptr;
    int   len;
} S3_String;

// Utility to translate string literals to S3_Strings
#define S3_S(X) (S3_String) { (X), sizeof(X)-1 }

enum {
    S3_OUT_OF_MEMORY = -1,
    S3_LIB_ERROR     = -2,
    S3_OTHER_ERROR   = -3,
};

// Writes the presigned URL in the dst buffer and
// returns the number of bytes written. No more than
// "cap" bytes are ever written. On error, a negative
// status code is returned:
//
//   S3_OUT_OF_MEMORY
//     An allocation failed or the output buffer is too small
//
//   S3_LIB_ERROR
//     The underlying crypto library failed
//
//   S3_OTHER_ERROR
//     Some other error
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
    int       cap);

#endif // S3_INCLUDED
