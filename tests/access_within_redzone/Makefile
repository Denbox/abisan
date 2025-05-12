CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wvla -O0 -std=c23

.PHONY: all clean fmt

all: access_within_red_zone

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c

clean:
	rm -f *.a *.o *.abisan.* access_within_red_zone

access_within_red_zone.o: access_within_red_zone.s
	ABISAN_TUNABLES_REDZONE_ENABLED=0 python3 ../../instrument.py access_within_red_zone.s
	$(CC) -c $(CFLAGS) $^.abisan.s -o $@

access_within_red_zone: main.c access_within_red_zone.o ../../libabisan_runtime.a
	$(CC) $(CFLAGS) $^ -o $@
