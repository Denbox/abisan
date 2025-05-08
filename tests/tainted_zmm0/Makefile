CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_zmm0

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_zmm0

tainted_zmm0.o: tainted_zmm0.s
	python3 ../../instrument.py tainted_zmm0.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_zmm0: main.c tainted_zmm0.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
