CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -D_DEFAULT_SOURCE
LDLIBS  = -lnetfilter_queue -lcrypto

secgw: secgw.o crypto.o pktutil.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c crypto.h pktutil.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o secgw

.PHONY: clean
