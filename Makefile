CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = eigensha
TEST_TARGETS = test1 test2

SRCS = main.c \
       sha256.c \
       sha512.c \
       sha3.c \
       keccak_f.c \
       sha_algo.c \
       eigensha.c \
       sha_ops.c \
       sha1.c

# This filters out main.o so you don't have two 'main' functions when linking the tests
OBJS = $(SRCS:.c=.o)
ALGO_OBJS = $(filter-out main.o, $(OBJS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

# Test executables
#   test1 <- test.c
#   test2 <- test2.c
# Each links its own test object with all SHA algorithm objects.
test: $(TEST_TARGETS)

test1: test.o $(ALGO_OBJS)
	$(CC) test.o $(ALGO_OBJS) -o $@
	@printf "\033[0;32m\342\234\224\033[0m Test build complete: ./$@\n"

test2: test2.o $(ALGO_OBJS)
	$(CC) test2.o $(ALGO_OBJS) -o $@
	@printf "\033[0;32m\342\234\224\033[0m Test build complete: ./$@\n"

# Build and run both test executables
check: $(TEST_TARGETS)
	./test1
	./test2

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGETS) test.o test2.o

re: clean all

.PHONY: all clean re test check
