CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_rdi_att

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_rdi_att

tainted_rdi_att.o: tainted_rdi_att.s
	python3 ../../instrument.py tainted_rdi_att.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_rdi_att: main.c tainted_rdi_att.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
