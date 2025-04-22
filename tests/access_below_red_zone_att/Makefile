CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: access_below_red_zone_att

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* access_below_red_zone_att

access_below_red_zone_att.o: access_below_red_zone_att.s
	python3 ../../instrument.py access_below_red_zone_att.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

access_below_red_zone_att: main.c access_below_red_zone_att.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
