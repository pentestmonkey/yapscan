CC=g++
DATADIR=/usr/local/share/yapscan/
BINDIR=/usr/local/bin/
YAPSCAN_VERSION=yapscan-0.7.6-beta

# Tip for optimising speed: Set march option in CFLAGS, e.g. -march=athlon-xp TODO detect this automatically

# If debugging
# CFLAGS=-g -Wall -Woverloaded-virtual -Wsign-promo -Wno-non-virtual-dtor -fno-inline # debugging flags
# DEBUGDEFINES=-DDEBUG

# If not debugging
CFLAGS=-s -Wall -Woverloaded-virtual -Wsign-promo -Wno-non-virtual-dtor -O3 -fomit-frame-pointer # normal flags
CFLAGS=-s -Wno-write-strings -O3 -fomit-frame-pointer # normal flags

# OpenSSL's MD5 library speeds up scanning.  If you have openssl installed, do this:
DEFINES=-DHAVE_LIBCRYPTO ${DEBUGDEFINES}
LDLIBS=-lpcap -lcrypto

# Otherwise do this:
# DEFINES=${DEBUGDEFINES}
# LDLIBS=-lpcap

# TODO Write good enough code to avoid these warning...
# CFLAGSTODO=-Weffc++ -Wold-style-cast

# TODO pass LDLIBS, LIBS through from configure.  Only compile md5.o if we need to.
OBJS=scanner.o scanner-port.o scanner-tcp.o scanner-udp.o scanner-icmp.o md5.o yapscan.o utils.o

all: yapscan

install: yapscan ports-tcp-all.txt ports-tcp-known.txt ports-tcp-common.txt ports-tcp-database.txt ports-udp-all.txt ports-udp-known.txt ports-udp-common.txt
	mkdir -p -m 0755 $(BINDIR) $(DATADIR)
	install -m 0755 -o root -g root yapscan $(BINDIR)
	install -m 0644 -o root -g root ports-tcp-all.txt $(DATADIR)
	install -m 0644 -o root -g root ports-tcp-known.txt $(DATADIR)
	install -m 0644 -o root -g root ports-tcp-common.txt $(DATADIR)
	install -m 0644 -o root -g root ports-udp-all.txt $(DATADIR)
	install -m 0644 -o root -g root ports-udp-known.txt $(DATADIR)
	install -m 0644 -o root -g root ports-udp-common.txt $(DATADIR)
	install -m 0644 -o root -g root ports-tcp-database.txt $(DATADIR)

yapscan: $(OBJS)
	$(CC) $(CFLAGS) ${OBJS} $(OPTS) $(LDLIBS) $(DEFINES) -o $@

static: $(OBJS)
	$(CC) $(STATICCFLAGS) ${OBJS} $(OPTS) $(LDLIBS) $(DEFINES) -static -o yapscan

efence: $(OBJS)
	$(CC) $(CFLAGS) ${OBJS} $(OPTS) $(LDLIBS) $(DEFINES) -lefence -o yapscan

utils.o: utils.cpp yapscan.h
	$(CC) $(CFLAGS) $(DEFINES) -c utils.cpp -o utils.o

yapscan.o: yapscan.cpp yapscan.h
	$(CC) $(CFLAGS) $(DEFINES) -c yapscan.cpp -o yapscan.o

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) $(DEFINES) -c md5.c -o md5.o

scanner-tcp.o: scanner-tcp.cpp scanner-tcp.h
	$(CC) $(CFLAGS) $(DEFINES) -c scanner-tcp.cpp -o scanner-tcp.o

scanner-port.o: scanner-port.cpp scanner-port.h
	$(CC) $(CFLAGS) $(DEFINES) -c scanner-port.cpp -o scanner-port.o

scanner-udp.o: scanner-udp.cpp scanner-udp.h
	$(CC) $(CFLAGS) $(DEFINES) -c scanner-udp.cpp -o scanner-udp.o

scanner-icmp.o: scanner-icmp.cpp scanner-icmp.h
	$(CC) $(CFLAGS) $(DEFINES) -c scanner-icmp.cpp -o scanner-icmp.o

scanner.o: scanner.cpp scanner.h
	$(CC) $(CFLAGS) $(DEFINES) -c scanner.cpp -o scanner.o

docs:
	pdflatex yapscan-user-docs.tex
	pdflatex yapscan-user-docs.tex
	pdflatex yapscan-user-docs.tex

dist:
	rm -rf $(YAPSCAN_VERSION)
	mkdir $(YAPSCAN_VERSION)
	cat dist-files.txt | xargs -I FILES cp FILES $(YAPSCAN_VERSION)
	tar --owner root --group 0 -cz -f $(YAPSCAN_VERSION).tar.gz $(YAPSCAN_VERSION)

clean:
	-rm -f *.o yapscan yapscan-user-docs.pdf
