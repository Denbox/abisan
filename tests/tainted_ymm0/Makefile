CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_ymm0

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_ymm0

tainted_ymm0.o: tainted_ymm0.s
	python3 ../../instrument.py tainted_ymm0.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_ymm0: main.c tainted_ymm0.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
