CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = eigensha
TEST_TARGET = test

SRCS = main.c \
       sha256.c \
       sha512.c \
       sha3.c \
       keccak_f.c \
       sha_algo.c \
       eigensha.c \
       sha_ops.c \
       sha1.c

# This filters out main.o so you don't have two 'main' functions when linking the test
OBJS = $(SRCS:.c=.o)
ALGO_OBJS = $(filter-out main.o, $(OBJS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

# New Test Target
# Links test.c (compiled to test.o) with all SHA algorithm objects
test: $(TEST_TARGET)

$(TEST_TARGET): test.o $(ALGO_OBJS)
	$(CC) test.o $(ALGO_OBJS) -o $(TEST_TARGET)
	@echo "\033[0;32m\u2714\033[0m Test build complete: ./$(TEST_TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET) test.o

re: clean all

.PHONY: all clean re test

# CC = gcc
# CFLAGS = -Wall -Wextra -O2

# TARGET = eigensha

# SRCS = main.c \
#        sha256.c \
#        sha512.c \
#        sha3.c \
#        keccak_f.c \
#        sha_algo.c \
#        eigensha.c \
#        sha_ops.c \
#        sha1.c

# OBJS = $(SRCS:.c=.o)

# all: $(TARGET)

# $(TARGET): $(OBJS)
# 	$(CC) $(OBJS) -o $(TARGET)

# %.o: %.c
# 	$(CC) $(CFLAGS) -c $< -o $@

# clean:
# 	rm -f $(OBJS) $(TARGET)

# re: clean all

# .PHONY: all clean re
