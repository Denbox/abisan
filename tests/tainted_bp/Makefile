CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_bp

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_bp

tainted_bp.o: tainted_bp.s
	python3 ../../instrument.py tainted_bp.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_bp: main.c tainted_bp.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
