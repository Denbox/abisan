CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_unused_arg

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_unused_arg

tainted_unused_arg.o: tainted_unused_arg.s
	python3 ../../instrument.py tainted_unused_arg.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_unused_arg: main.c tainted_unused_arg.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
