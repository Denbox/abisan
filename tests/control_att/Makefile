CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: control_att

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* control_att

control_att.o: control_att.s
	python3 ../../instrument.py control_att.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

control_att: main.c control_att.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
