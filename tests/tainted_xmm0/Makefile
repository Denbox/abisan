CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_xmm0

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_xmm0

tainted_xmm0.o: tainted_xmm0.s
	python3 ../../instrument.py tainted_xmm0.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_xmm0: main.c tainted_xmm0.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
