CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_rsp

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_rsp

clobber_rsp.o: clobber_rsp.s
	python3 ../../instrument.py clobber_rsp.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_rsp: main.s clobber_rsp.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
