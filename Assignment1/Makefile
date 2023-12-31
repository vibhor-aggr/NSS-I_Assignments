
compile : sudo fput fget setacl getacl create_dir cd
	sudo chown fakeroot:fakeroot sudo fput fget setacl getacl create_dir cd option.o utils.o uid.o
	sudo chmod u+s fput fget setacl getacl create_dir cd
	sudo setcap cap_setuid+ep fput cap_setuid+ep fget cap_setuid+ep setacl cap_setuid+ep getacl cap_setuid+ep create_dir cap_setuid+ep cd

sudo : sudo.c 
	gcc -g -o sudo sudo.c

fput : fput.c utils.o uid.o
	gcc -g -o fput fput.c utils.o uid.o

fget : fget.c utils.o uid.o
	gcc -g -o fget fget.c utils.o uid.o

setacl : setacl.c utils.o uid.o option.o
	gcc -g -o setacl setacl.c utils.o uid.o option.o

getacl : getacl.c utils.o uid.o
	gcc -g -o getacl getacl.c utils.o uid.o

create_dir : create_dir.c utils.o uid.o option.o
	gcc -g -o create_dir create_dir.c utils.o uid.o option.o

cd : cd.c utils.o uid.o
	gcc -g -o cd cd.c utils.o uid.o

utils.o : utils.c
	gcc -g -c utils.c

uid.o : uid.c
	gcc -g -c uid.c

option.o : option.c
	gcc -g -c option.c
