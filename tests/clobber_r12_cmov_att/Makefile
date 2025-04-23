CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: clobber_r12_cmov_att

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* clobber_r12_cmov_att

clobber_r12_cmov_att.o: clobber_r12_cmov_att.s
	python3 ../../instrument.py clobber_r12_cmov_att.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

clobber_r12_cmov_att: main.c clobber_r12_cmov_att.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
