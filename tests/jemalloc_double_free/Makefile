.PHONY: all, clean
CC = gcc
LDFLAGS += -no-pie -ljemalloc

BINS = double_free.bin 
OBJECTS = $(BINS:.bin=.o)
SOURCES = $(BINS:.bin=.c)
RESULTS = $(BINS:.bin=.bin-result.yaml)
DESCS = $(BINS:.bin=.bin-desc.yaml)
POCS = ./*/pocs

all: $(BINS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

%.bin: %.o
	$(CC) -L. -o $@ $^ $(LDFLAGS) -lc

clean:
	rm -rf $(OBJECTS) $(RESULTS) $(DESCS) $(POCS)

distclean:
	rm -rf $(BINS) $(OBJECTS) $(RESULTS) $(DESCS) $(POCS)
