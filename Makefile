CFLAGS  ?= -Wall -Wextra -pedantic -Werror -g -O0
LDFLAGS ?=

.PHONY: captrace default static clean

default: captrace

static: LDFLAGS += -static

static captrace: captrace.c
	$(CC) $(CFLAGS) -o captrace $< $(LDFLAGS)

clean:
	rm -f captrace
