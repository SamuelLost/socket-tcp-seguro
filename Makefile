CC = gcc
FLAGS = -g -lcrypto
SOURCE_FOLDER = src/
SOURCE_CLIENT = $(SOURCE_FOLDER)cliente-seguro.c
SOURCE_SERVER = $(SOURCE_FOLDER)server-seguro.c

all:
	$(CC) $(SOURCE_CLIENT) $(FLAGS) -o bin/client;
	$(CC) $(SOURCE_SERVER) $(FLAGS) -o bin/server;

clean:
	rm bin/*;
