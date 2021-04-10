MODNAME=mod_metidox.so
MODOBJ=mod_metidox.o helpers.o
MODCFLAGS=-Wall -Werror
MODLDFLAGS=-ltoxcore -lsodium

FS_INCLUDES ?=/usr/local/freeswitch/include/freeswitch
FS_MODULES ?=/usr/local/freeswitch/mod

CC=gcc
CFLAGS=-fPIC -g -ggdb -I$(FS_INCLUDES) $(MODCFLAGS)
LDFLAGS=$(MODLDFLAGS)
 
.PHONY: all
all: $(MODNAME)
 
$(MODNAME): $(MODOBJ)
	$(CC) -shared -o $@ $(MODOBJ) $(LDFLAGS)

.c.o: $<
	$(CC) $(CFLAGS) -o $@ -c $<
 
.PHONY: clean
clean:
	rm -f $(MODNAME) $(MODOBJ)
 
.PHONY: install
install: $(MODNAME)
	install $(MODNAME) $(FS_MODULES)
