ifdef STATIC
  CFLAGS+=-DSTATIC
  LDFLAGS+=-static
endif

LUA?=lua
LUALIBS?=$(shell pkg-config --libs $(LUA))
LUAINC?=$(shell pkg-config --cflags $(LUA))

OSNAME?=$(shell uname -s | tr A-Z a-z)
OSREL?=$(shell uname -r)
OSRELMAJOR?=$(shell uname -r | cut -f1 -d.)

ifeq (freebsd,$(OSNAME))
  LDFLAGS+=-lkvm
endif

CFLAGS+=-DOSNAME=$(OSNAME) -DOSREL=$(OSREL) -DOSRELMAJOR=$(OSRELMAJOR)

OBJS_RXD = iptypes.o hcache.o md5.o n2acl.o n2args.o n2config.o n2diskdb.o \
	   n2encoding.o n2pingdb.o n2rxd.o n2hostlog.o n2malloc.o

OBJS_TXD = iptypes.o md5.o n2args.o n2config.o n2acl.o n2encoding.o \
	   n2txd.o n2stat-$(OSNAME).o tproc.o n2hostlog.o n2malloc.o proctitle.o \
	   http_fetcher.o http_error_codes.o xenvps.o

OBJS_TXD_DEBUG = iptypes.o md5.o n2args.o n2config.o n2acl.o n2encoding.o \
                 n2txd-debug.o n2stat-$(OSNAME)-debug.o tproc.o n2hostlog.o \
                 n2malloc.o proctitle.o http_fetcher.o \
                 http_error_codes.o xenvps.o

OBJS_ANALYZE = n2analyze.o n2diskdb.o n2encoding.o md5.o n2hostlog.o \
               iptypes.o n2malloc.o

OBJS_PING = n2ping.o iptypes.o n2pingdb.o n2malloc.o

OBJS_HSTAT = n2encoding.o iptypes.o n2diskdb.o n2hstat.o md5.o n2hostlog.o n2malloc.o

OBJS_RECONF = n2reconf.o n2malloc.o

OBJS_HIST = n2encoding.o iptypes.o n2diskdb.o n2history.o md5.o n2hostlog.o n2malloc.o

OBJS_RAW = n2encoding.o iptypes.o n2diskdb.o n2rawdat.o md5.o n2hostlog.o n2malloc.o

OBJS_DUMP = n2encoding.o iptypes.o n2diskdb.o n2dump.o md5.o n2hostlog.o n2malloc.o

OBJS_PGREP = n2encoding.o iptypes.o n2diskdb.o n2pgrep.o md5.o n2hostlog.o n2malloc.o

OBJS_GROUPS = n2encoding.o iptypes.o n2diskdb.o n2config.o n2acl.o \
	      n2groups.o md5.o n2args.o n2hostlog.o n2malloc.o

OBJS_CONTACT = iptypes.o n2config.o n2acl.o n2args.o n2malloc.o n2contact.o

OBJS_CONTROL = n2control.o n2malloc.o

OBJS_CONFTOOL = n2conftool.o iptypes.o n2config.o n2acl.o n2args.o n2malloc.o n2encoding.o md5.o n2hostlog.o

all: n2txd n2rxd n2ping n2hstat n2control n2history n2dump n2groups \
	 n2reconf n2pgrep n2analyze n2rawdat n2contact

install: all
	@echo "##########################################################################"
	@echo "The install script will use adduser to create a user n2 if it does not "
	@echo "exist. Type 'make reallyinstall' if you think that is just swell. Create "
	@echo "an n2 user+group first and type 'make justinstall' to bypass the adduser "
	@echo "magic and just install the binaries as user/group n2."
	@echo "##########################################################################"

justinstall: all
	install -d -o root -g root -m 0755 $(DESTDIR)/var/state
	install -d -o root -g root -m 0755 $(DESTDIR)/etc/n2
	install -d -o root -g root -m 0755 $(DESTDIR)/var/state/n2
	install -d -o n2 -g n2 -m 0750 $(DESTDIR)/var/state/n2/ping
	install -d -o n2 -g n2 -m 0750 $(DESTDIR)/var/state/n2/tmp
	install -d -o n2 -g n2 -m 0750 $(DESTDIR)/var/state/n2/current
	install -d -o n2 -g n2 -m 0750 $(DESTDIR)/var/state/n2/events
	install -d -o n2 -g n2 -m 0750 $(DESTDIR)/var/state/n2/log
	install -d -o n2 -g n2 -m 0750 $(DESTDIR)/var/log/n2
	install -b -o root -g root -m 0644 n2rxd.example.conf $(DESTDIR)/etc/n2/
	install -b -o root -g root -m 0644 n2txd.example.conf $(DESTDIR)/etc/n2/
	install -o root -g n2 -m 0755 n2rxd $(DESTDIR)/usr/sbin/
	install -o root -g n2 -m 0755 n2txd $(DESTDIR)/usr/sbin/
	install -o root -g n2 -m 0755 n2ping $(DESTDIR)/usr/sbin/
	install -o root -g n2 -m 0755 n2hstat $(DESTDIR)/usr/bin/
	install -o root -g n2 -m 0755 n2pgrep $(DESTDIR)/usr/bin/
	install -o root -g n2 -m 0755 n2conftool $(DESTDIR)/usr/bin/
	install -o root -g n2 -m 0755 n2history $(DESTDIR)/usr/bin/
	install -o root -g n2 -m 0755 n2rawdat $(DESTDIR)/usr/bin/
	install -o root -g n2 -m 0755 n2control $(DESTDIR)/usr/bin/
	install -o root -g n2 -m 0755 n2groups $(DESTDIR)/usr/bin/
	install -o root -g n2 -m 0755 n2contact $(DESTDIR)/usr/bin/

reallyinstall: all
	install -d -o root -g root -m 0755 /var/state
	./mkuser
	install -d -o root -g root -m 0755 /etc/n2
	install -d -o root -g root -m 0755 /var/state/n2
	install -d -o n2 -g n2 -m 0750 /var/state/n2/ping
	install -d -o n2 -g n2 -m 0750 /var/state/n2/tmp
	install -d -o n2 -g n2 -m 0750 /var/state/n2/current
	install -d -o n2 -g n2 -m 0750 /var/state/n2/log
	install -d -o n2 -g n2 -m 0750 /var/state/n2/events
	install -d -o n2 -g n2 -m 0750 /var/log/n2
	install -b -o root -g root -m 0644 n2rxd.example.conf /etc/n2/
	install -b -o root -g root -m 0644 n2txd.example.conf /etc/n2/
	install -o root -g n2 -m 4750 n2rxd /usr/sbin/
	install -o root -g n2 -m 4750 n2txd /usr/sbin/
	install -o root -g n2 -m 4750 n2ping /usr/sbin/
	install -o root -g n2 -m 0750 n2hstat /usr/bin/
	install -o root -g n2 -m 0750 n2pgrep /usr/bin/
	install -o root -g n2 -m 2750 n2conftool /usr/bin/
	install -o root -g n2 -m 0750 n2history /usr/bin/
	install -o root -g n2 -m 0750 n2rawdat /usr/bin/
	install -o root -g n2 -m 4750 n2control /usr/bin/
	install -o root -g n2 -m 0750 n2groups /usr/bin/

n2analyze: $(OBJS_ANALYZE)
	$(CC) -o n2analyze $(OBJS_ANALYZE) $(LUALIBS)

n2acl-test: n2acl-test.o n2malloc.o
	$(CC) $(LDFLAGS) -o n2acl-test n2acl-test.o n2malloc.o

n2contact: $(OBJS_CONTACT)
	$(CC) $(LDFLAGS) -o n2contact $(OBJS_CONTACT)

n2dump: $(OBJS_DUMP)
	$(CC) $(LDFLAGS) -o n2dump $(OBJS_DUMP)

n2conftool: $(OBJS_CONFTOOL)
	$(CC) $(LDFLAGS) -o n2conftool $(OBJS_CONFTOOL)

n2groups: $(OBJS_GROUPS)
	$(CC) $(LDFLAGS) -o n2groups $(OBJS_GROUPS)

n2reconf: $(OBJS_RECONF)
	$(CC) $(LDFLAGS) -o n2reconf $(OBJS_RECONF)

n2control: $(OBJS_CONTROL)
	$(CC) $(LDFLAGS) -o n2control $(OBJS_CONTROL)

n2txd: $(OBJS_TXD)
	$(CC) $(LDFLAGS) -o n2txd $(OBJS_TXD)
	
n2txd-debug: $(OBJS_TXD_DEBUG)
	$(CC) $(LDFLAGS) -o n2txd-debug $(OBJS_TXD_DEBUG)

n2rxd: $(OBJS_RXD)
	$(CC) $(LDFLAGS) -o n2rxd $(OBJS_RXD) -lpthread

n2ping: $(OBJS_PING)
	$(CC) $(LDFLAGS) -o n2ping $(OBJS_PING) -lpthread

n2hstat: $(OBJS_HSTAT)
	$(CC) $(LDFLAGS) -o n2hstat $(OBJS_HSTAT)

n2history: $(OBJS_HIST)
	$(CC) $(LDFLAGS) -o n2history $(OBJS_HIST)

n2rawdat: $(OBJS_RAW)
	$(CC) $(LDFLAGS) -o n2rawdat $(OBJS_RAW)

n2pgrep: $(OBJS_PGREP)
	$(CC) $(LDFLAGS) -o n2pgrep $(OBJS_PGREP)

n2analyze.o: n2analyze.c
	$(CC) $(LUAINC) -c n2analyze.c

n2acl-test.o: n2acl.c n2acl.h
	$(CC) $(LDFLAGS) -DUNIT_TEST -c n2acl.c -o n2acl-test.o

n2txd-debug.o:
	$(CC) $(LDFLAGS) $(LDFLAGS) -DDEBUG -I. -c n2txd.c -o n2txd-debug.o
	
n2stat-$(OSNAME)-debug.o:
	$(CC) $(LDFLAGS) -DDEBUG -I. -c n2stat-$(OSNAME).c -o n2stat-$(OSNAME)-debug.o

clean:
	rm -f *.o n2acl-test n2dump n2conftool n2groups n2reconf n2control n2txd n2txd-debug n2rxd n2ping n2hstat n2history n2rawdat n2pgrep n2contact



.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -I. -c $<
