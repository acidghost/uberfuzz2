CC=gcc
CFLAGS=-Wall -O3 -std=c11
LDLIBS=-lzmq -lcollectc

BIN := driver

SRCS := $(sort $(wildcard *.c))
OBJS := $(SRCS:.c=.o)

ifeq ($(DEBUG), 1)
CFLAGS += -g
endif

.PHONY: clean
all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	rm -rf $(BIN) $(OBJS)
