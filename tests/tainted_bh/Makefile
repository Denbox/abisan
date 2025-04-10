CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_bh

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_bh

tainted_bh.o: tainted_bh.s
	python3 ../../instrument.py tainted_bh.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_bh: main.c tainted_bh.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
