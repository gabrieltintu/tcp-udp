# TINTU Gabriel-Claudiu 323CAb - 2023-2024

CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -g

TARGETS = server subscriber

build: $(TARGETS)

server: server.cpp common.cpp
	$(CC) $(CFLAGS) server.cpp common.cpp -o server

subscriber: subscriber.cpp common.cpp
	$(CC) $(CFLAGS) subscriber.cpp common.cpp -o subscriber

pack:
	zip -FSr 323CA_Tintu_GabrielClaudiu_Tema2.zip readme.txt Makefile *.cpp *.hpp

clean:
	rm -f $(TARGETS)

.PHONY: pack clean
