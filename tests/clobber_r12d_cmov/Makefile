CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r12d_cmov

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r12d_cmov

clobber_r12d_cmov.o: clobber_r12d_cmov.s
	python3 ../../instrument.py clobber_r12d_cmov.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r12d_cmov: main.c clobber_r12d_cmov.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
