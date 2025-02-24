CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: control

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* control

control.o: control.s
	python3 ../../instrument.py control.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

control: main.c control.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
