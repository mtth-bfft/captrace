MAKEFLAGS += --no-builtin-rules
.PHONY: clean

DEBUG   ?= false
CFLAGS  ?= -std=c11 -Wall -Wextra -pedantic -Werror
LDFLAGS ?= -static
SOURCES ?= $(wildcard *.c)

ifeq ($(DEBUG),false)
	CFLAGS += -O2
else
	CFLAGS += -g -O0
endif

captrace: $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f captrace *.o
