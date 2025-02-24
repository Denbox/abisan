CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_rbx

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_rbx

clobber_rbx.o: clobber_rbx.s
	python3 ../../instrument.py clobber_rbx.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_rbx: main.c clobber_rbx.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
