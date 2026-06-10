CC ?= gcc
CFLAGS ?= -g -Wall -Wextra
BINARIES = sudo fput fget setacl getacl create_dir cd
OBJECTS = option.o utils.o uid.o

.PHONY: compile all clean install-privileged

compile all: $(BINARIES)

install-privileged: $(BINARIES)
	sudo chown fakeroot:fakeroot $(BINARIES)
	sudo chmod u+s fput fget setacl getacl create_dir cd
	sudo setcap cap_setuid+ep fput cap_setuid+ep fget cap_setuid+ep setacl cap_setuid+ep getacl cap_setuid+ep create_dir cap_setuid+ep cd

clean:
	rm -f $(BINARIES) $(OBJECTS)

sudo : sudo.c 
	$(CC) $(CFLAGS) -o sudo sudo.c

fput : fput.c utils.o uid.o
	$(CC) $(CFLAGS) -o fput fput.c utils.o uid.o

fget : fget.c utils.o uid.o
	$(CC) $(CFLAGS) -o fget fget.c utils.o uid.o

setacl : setacl.c utils.o uid.o option.o
	$(CC) $(CFLAGS) -o setacl setacl.c utils.o uid.o option.o

getacl : getacl.c utils.o uid.o
	$(CC) $(CFLAGS) -o getacl getacl.c utils.o uid.o

create_dir : create_dir.c utils.o uid.o option.o
	$(CC) $(CFLAGS) -o create_dir create_dir.c utils.o uid.o option.o

cd : cd.c utils.o uid.o
	$(CC) $(CFLAGS) -o cd cd.c utils.o uid.o

utils.o : utils.c
	$(CC) $(CFLAGS) -c utils.c

uid.o : uid.c
	$(CC) $(CFLAGS) -c uid.c

option.o : option.c
	$(CC) $(CFLAGS) -c option.c
