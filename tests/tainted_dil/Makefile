CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_dil

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_dil

tainted_dil.o: tainted_dil.s
	python3 ../../instrument.py tainted_dil.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_dil: main.c tainted_dil.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
