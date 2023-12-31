compile: server_real client_real

server_real: server_real.c
	gcc -o server_real server_real.c -lpthread -lssl -lcrypto

client_real: client_real.c
	gcc -o client_real client_real.c random.c -lpthread -lssl -lcrypto

