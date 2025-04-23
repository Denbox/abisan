CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: control_access_below_red_zone_att

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* control_access_below_red_zone_att

control_access_below_red_zone_att.o: control_access_below_red_zone_att.s
	python3 ../../instrument.py control_access_below_red_zone_att.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

control_access_below_red_zone_att: main.c control_access_below_red_zone_att.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
