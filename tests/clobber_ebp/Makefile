CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_ebp

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_ebp

clobber_ebp.o: clobber_ebp.s
	python3 ../../instrument.py clobber_ebp.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_ebp: main.c clobber_ebp.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
