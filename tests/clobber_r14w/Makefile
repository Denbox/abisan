CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r14w

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r14w

clobber_r14w.o: clobber_r14w.s
	python3 ../../instrument.py clobber_r14w.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r14w: main.c clobber_r14w.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
