CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_bpl

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_bpl

clobber_bpl.o: clobber_bpl.s
	python3 ../../instrument.py clobber_bpl.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_bpl: main.c clobber_bpl.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
