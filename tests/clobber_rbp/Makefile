CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_rbp

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_rbp

clobber_rbp.o: clobber_rbp.s
	python3 ../../instrument.py clobber_rbp.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_rbp: main.c clobber_rbp.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
