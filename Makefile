CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = eigensha

SRCS = main.c \
       sha256.c \
       sha512.c \
       sha3.c \
       keccak_f.c \
       sha_algo.c \
       eigensha.c \
       sha_ops.c \
       sha1.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

re: clean all

.PHONY: all clean re
