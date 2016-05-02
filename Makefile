CC=gcc
CFLAGS=-Wall -g3 -O2
LDFLAGS=-lgcrypt

CODE=$(wildcard *.c)

LIBS=$(filter %lib.c, $(CODE))
OBJS=$(patsubst %.c,%.o,$(LIBS))

SRC=$(filter-out %lib.c,$(CODE))
BINS=$(patsubst %.c,%,$(SRC))

all: $(OBJS) $(BINS)

$(BINS): $(OBJS)
	$(CC) $(CFLAGS) -o $@  $@.c $(OBJS) $(LDFLAGS)

$(OBJS): $(patsubst %.o,%.c,$@)
	$(CC) $(CFLAGS) -c -fPIC -o $@ $(patsubst %.o,%.c,$@)

clean:
	rm -f $(OBJS) $(BINS)
