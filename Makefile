ifeq ($(shell uname -s),Linux)
	LFLAGS = -lcrypto
else
	LFLAGS = -lbcrypt
endif

all:
	cc s3.c test/generate_test_url.c -o test/generate_test_url -Wall -Wextra $(LFLAGS) -ggdb
