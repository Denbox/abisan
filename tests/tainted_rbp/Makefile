CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_rbp

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_rbp

tainted_rbp.o: tainted_rbp.s
	python3 ../../instrument.py tainted_rbp.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_rbp: main.c tainted_rbp.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
