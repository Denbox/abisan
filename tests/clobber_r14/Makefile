CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r14

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r14

clobber_r14.o: clobber_r14.s
	python3 ../../instrument.py clobber_r14.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r14: main.c clobber_r14.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
