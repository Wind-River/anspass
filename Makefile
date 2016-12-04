CC ?= gcc
CFLAGS ?= -Wall -g3 -O2
LDFLAGS ?= -lgcrypt

VERSION ?= 1.0
CPPFLAGS ?= -DVERSION=\"$(VERSION)\"

DESTDIR ?=
bindir ?= /usr/bin

BINS = anspassd anspass anspass-ctrl
LIBS = anspass-lib.o

all: $(LIBS) $(BINS)

$(BINS): $(LIBS)

# Make sure if a header changes, the .c is rebuilt
%.c: %.h
	-@touch $@

install: all
	-@if [ ! -d $(DESTDIR)$(bindir) ]; then mkdir -p $(DESTDIR)$(bindir); fi
	cp $(BINS) $(DESTDIR)$(bindir)


.PHONY: clean
clean:
	rm -f $(OBJS) $(BINS) $(LIBS)
