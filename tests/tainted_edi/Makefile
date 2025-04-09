CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_edi

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_edi

tainted_edi.o: tainted_edi.s
	python3 ../../instrument.py tainted_edi.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_edi: main.c tainted_edi.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
