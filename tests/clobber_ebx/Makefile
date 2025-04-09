CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_ebx

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_ebx

clobber_ebx.o: clobber_ebx.s
	python3 ../../instrument.py clobber_ebx.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_ebx: main.c clobber_ebx.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
