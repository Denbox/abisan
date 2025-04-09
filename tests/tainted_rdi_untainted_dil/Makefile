CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_rdi_untainted_dil

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_rdi_untainted_dil

tainted_rdi_untainted_dil.o: tainted_rdi_untainted_dil.s
	python3 ../../instrument.py tainted_rdi_untainted_dil.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_rdi_untainted_dil: main.c tainted_rdi_untainted_dil.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
