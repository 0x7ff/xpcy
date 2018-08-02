CC ?= clang
CFLAGS ?= -Wall -Wextra -pedantic -std=c99 -O2

.PHONY: all
all:
	$(CC) $(CFLAGS) xpcy.c -o xpcy

.PHONY: bonus
bonus:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything xpc_list.c -o xpc_list -framework CoreFoundation

.PHONY: clean
clean:
	$(RM) xpcy
