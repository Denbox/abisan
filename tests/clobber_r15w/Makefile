CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r15w

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r15w

clobber_r15w.o: clobber_r15w.s
	python3 ../../instrument.py clobber_r15w.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r15w: main.c clobber_r15w.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
