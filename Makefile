ifeq ($(shell uname -s),Linux)
	LFLAGS = -lcrypto
else
	LFLAGS = -lbcrypt
endif

all:
	cc s3.c test.c -o test -Wall -Wextra $(LFLAGS) -ggdb
