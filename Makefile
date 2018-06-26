all:
	gcc -g -o tlsev main.c -levent -lssl -lcrypto
	
