CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: test abisan_test

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *_instrumented_by_abisan.s test abisan_test

abisan_runtime.o: abisan_runtime.c
	$(CC) -c $(CFLAGS) $^ -o $@

abisan_instrumentation.o: abisan_instrumentation.s
	$(CC) -c $(CFLAGS) $^ -o $@

libabisan_runtime.a: abisan_runtime.o abisan_instrumentation.o
	$(AR) rs $@ $^

f_instrumented_by_abisan.s: f.s
	python3 instrument.py $^ > $@

f.o: f.s
	$(CC) -c $(CFLAGS) $^ -o $@

f_instrumented_by_abisan.o: f_instrumented_by_abisan.s
	$(CC) -c $(CFLAGS) $^ -o $@

main.o: main.c
	$(CC) -c $(CFLAGS) $^ -o $@

abisan_test: main.o f_instrumented_by_abisan.o libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@

test: main.o f.o
	$(CC) $(CFLAGS) $^ -o $@
