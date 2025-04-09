CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_di

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_di

tainted_di.o: tainted_di.s
	python3 ../../instrument.py tainted_di.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_di: main.c tainted_di.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
