CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_bpl

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_bpl

tainted_bpl.o: tainted_bpl.s
	python3 ../../instrument.py tainted_bpl.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_bpl: main.c tainted_bpl.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
