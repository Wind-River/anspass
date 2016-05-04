CC=gcc
CFLAGS=-Wall -g3 -O2
LDFLAGS=-lgcrypt

CODE=$(wildcard *.c)

LIBS=$(filter %lib.c, $(CODE))
OBJS=$(patsubst %.c,%.o,$(LIBS))

SRC=$(filter-out %lib.c,$(CODE))
BINS=$(patsubst %.c,%,$(SRC))

all: $(OBJS) $(BINS)

$(BINS): % : %.h $(OBJS)
	$(CC) $(CFLAGS) -o $@  $@.c $(OBJS) $(LDFLAGS)

$(OBJS): %.o : %.h
	$(CC) $(CFLAGS) -c -fPIC -o $@ $(patsubst %.o,%.c,$@)


.PHONY: clean
clean:
	rm -f $(OBJS) $(BINS)
