CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -g

all: server subscriber

server: server.cpp common.cpp
	$(CC) $(CFLAGS) server.cpp common.cpp -o server

subscriber: subscriber.cpp common.cpp
	$(CC) $(CFLAGS) subscriber.cpp common.cpp -o subscriber

clean:
	rm -f server subscriber
