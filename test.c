#include <stdio.h>
#include "s3.h"

int main(void)
{
    char dst[1<<10];
    int len = s3_presign_url(
        S3_S("bucket"),
        S3_S("object"),
        S3_S("GET"),
        3600,
        S3_S(""),
        S3_S("minioadmin"),
        S3_S("minioadmin"),
        S3_S("us-west-1"),
        S3_S("s3"),
        S3_S("172.17.0.2:9000"),
        time(NULL),
        dst, sizeof(dst));
    if (len < 0) {
        fprintf(stderr, "Failed (ret=%d)\n", len);
        return -1;
    }

    printf("Success! (ret=%d)\n\n%.*s\n", len, len, dst);
    return 0;
}
