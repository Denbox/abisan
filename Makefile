CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: test

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c *.h

clean:
	rm -f *.a *.o *_instrumented_by_abisan.s test

abisan_runtime.o: abisan_runtime.c
	$(CC) -c $(CFLAGS) $^ -o $@

abisan_instrumentation.o: abisan_instrumentation.s
	$(CC) -c $(CFLAGS) $^ -o $@

libabisan_runtime.a: abisan_runtime.o abisan_instrumentation.o
	$(AR) rs $@ $^

f.o: f.s
	python3 instrument.py $^ > $^_instrumented_by_abisan.s
	$(CC) -c $(CFLAGS) $^_instrumented_by_abisan.s -o $@


main.o: main.c
	$(CC) -c $(CFLAGS) $^ -o $@

test: main.o f.o libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
