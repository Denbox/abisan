CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r15d

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r15d

clobber_r15d.o: clobber_r15d.s
	python3 ../../instrument.py clobber_r15d.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r15d: main.c clobber_r15d.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
