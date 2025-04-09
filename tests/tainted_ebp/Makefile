CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_ebp

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_ebp

tainted_ebp.o: tainted_ebp.s
	python3 ../../instrument.py tainted_ebp.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_ebp: main.c tainted_ebp.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
