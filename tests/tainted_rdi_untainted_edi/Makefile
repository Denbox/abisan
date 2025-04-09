CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_rdi_untainted_edi

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_rdi_untainted_edi

tainted_rdi_untainted_edi.o: tainted_rdi_untainted_edi.s
	python3 ../../instrument.py tainted_rdi_untainted_edi.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_rdi_untainted_edi: main.c tainted_rdi_untainted_edi.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
