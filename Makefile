CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: test

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c *.h

clean:
	rm -f *.o test

abisan_runtime.o: abisan_runtime.c
	$(CC) -c $(CFLAGS) $^ -o $@

abisan_instrumentation.o: abisan_instrumentation.s
	$(CC) -c $(CFLAGS) $^ -o $@

f.o: f.s
	$(CC) -c $(CFLAGS) $^ -o $@

main.o: main.c
	$(CC) -c $(CFLAGS) $^ -o $@

test: main.o f.o abisan_instrumentation.o abisan_runtime.o
	$(CC) $(CFLAGS) $^ -o $@
