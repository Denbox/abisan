CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_rdi_untainted_di

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_rdi_untainted_di

tainted_rdi_untainted_di.o: tainted_rdi_untainted_di.s
	python3 ../../instrument.py tainted_rdi_untainted_di.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_rdi_untainted_di: main.c tainted_rdi_untainted_di.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
