CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_rdi

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_rdi

tainted_rdi.o: tainted_rdi.s
	python3 ../../instrument.py tainted_rdi.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_rdi: main.c tainted_rdi.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
