CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: tainted_rdi_into_heap

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* tainted_rdi_into_heap

tainted_rdi_into_heap.o: tainted_rdi_into_heap.s
	python3 ../../instrument.py tainted_rdi_into_heap.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

tainted_rdi_into_heap: main.c tainted_rdi_into_heap.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
