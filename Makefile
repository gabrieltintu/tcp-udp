CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -g

all: server subscriber

server: server.cpp common.c
	$(CC) $(CFLAGS) server.cpp common.c -o server

subscriber: subscriber.cpp common.c
	$(CC) $(CFLAGS) subscriber.cpp common.c -o subscriber

clean:
	rm -f server subscriber
