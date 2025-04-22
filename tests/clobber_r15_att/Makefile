CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r15_att

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r15_att

clobber_r15_att.o: clobber_r15_att.s
	python3 ../../instrument.py clobber_r15_att.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r15_att: main.c clobber_r15_att.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
