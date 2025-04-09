CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r14d

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r14d

clobber_r14d.o: clobber_r14d.s
	python3 ../../instrument.py clobber_r14d.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r14d: main.c clobber_r14d.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
