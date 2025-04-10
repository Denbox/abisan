CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_bh

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_bh

clobber_bh.o: clobber_bh.s
	python3 ../../instrument.py clobber_bh.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_bh: main.c clobber_bh.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
