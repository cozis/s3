all:
	cc s3.c test.c -o test -Wall -Wextra -lcrypto -ggdb
