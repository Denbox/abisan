CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: test

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c *.h

clean:
	rm -f test *.o

test: test.c f.s abisan_runtime.c abisan_f_instrumentation.s
	$(CC) -static $(CFLAGS) $^ -o $@
