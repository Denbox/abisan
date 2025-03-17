CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r12

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r12

clobber_r12.o: clobber_r12.s
	python3 ../../instrument.py clobber_r12.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r12: main.c clobber_r12.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
