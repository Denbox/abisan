CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r13w

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r13w

clobber_r13w.o: clobber_r13w.s
	python3 ../../instrument.py clobber_r13w.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r13w: main.c clobber_r13w.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
