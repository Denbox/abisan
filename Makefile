CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt test

all: libabisan_runtime.a

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o && sh -c 'for thing in tests/*; do pushd "$$thing" && make clean && popd; done'


test: libabisan_runtime.a
	./run_tests.bash

abisan_runtime.o: abisan_runtime.c
	$(CC) -c $(CFLAGS) $^ -o $@

abisan_instrumentation.o: abisan_instrumentation.s
	$(CC) -c $(CFLAGS) $^ -o $@

libabisan_runtime.a: abisan_runtime.o abisan_instrumentation.o
	$(AR) rs $@ $^
