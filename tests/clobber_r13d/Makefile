CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r13d

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r13d

clobber_r13d.o: clobber_r13d.s
	python3 ../../instrument.py clobber_r13d.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r13d: main.c clobber_r13d.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
