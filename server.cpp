#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <vector>
#include <poll.h>
#include <set>
#include <algorithm>
#include "helpers.h"
#include "common.h"

// using namespace std;

std::ofstream fout("file_server.out");

#define MAX_LEN 100
#define MAX_TOPIC 50
#define MAX_CONTENT 1500

struct udp_message {
	char topic[MAX_TOPIC];
	int data_type;
	char content[MAX_CONTENT];
};

struct subscriber {
	bool connected;
	std::set<std::string> subscribed_topics;
	int sock_fd;
	std::string client_id;
};

// struct tcp_message {};

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	// check arg
	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <PORT>\n";
		return EXIT_FAILURE;
	}

	std::vector<pollfd> poll_fds;
	std::vector<subscriber> subscribers;

	int num_sockets = 1;
	int rc;
	// set port
	uint16_t port;
	rc = sscanf(argv[1], "%hu", &port);
	DIE(rc != 1, "Given port is invalid");
	fout << "server: " << port << "\n";
	fout.flush();

	// create TCP socket
	int sock_tcp;
	struct sockaddr_in serv_addr;
	socklen_t socket_len = sizeof(struct sockaddr_in);


	// creare socket pt TCP + bind + listen
	sock_tcp = socket(AF_INET, SOCK_STREAM, 0);

	// Facem adresa socket-ului reutilizabila, ca sa nu primim eroare in caz ca
	// rulam de 2 ori rapid
	const int enable = 1;
	if (setsockopt(sock_tcp, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		perror("setsockopt(SO_REUSEADDR) failed");
	

	memset(&serv_addr, 0, socket_len);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	DIE(sock_tcp < 0, "eroare socket - tcp\n");
	rc = bind(sock_tcp, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "eroare bind - tcp\n");
	rc = listen(sock_tcp, SOMAXCONN / 4);
	DIE(rc < 0, "eroare listen - udp\n");
	

	// Adaugam noul file descriptor (socketul pe care se asculta conexiuni) in
	// multimea poll_fds
	pollfd listen_poll_fd;
	listen_poll_fd.fd = sock_tcp;
	listen_poll_fd.events = POLLIN;

	// Push back the listen pollfd structure into the vector
	poll_fds.push_back(listen_poll_fd);

	// std::cout << "Server is running on port " << port << std::endl;
	fout << "inainte de while\n";
	fout.flush();

	pollfd stdin_poll_fd;
	stdin_poll_fd.fd = STDIN_FILENO;
	stdin_poll_fd.events = POLLIN;
	poll_fds.push_back(stdin_poll_fd);
	num_sockets++;
	
	bool running = true;


	while (running) {
		// exit command 
		char buff[MAX_LEN];
		
		rc = poll(poll_fds.data(), poll_fds.size(), -1);
   	 	DIE(rc < 0, "poll");

		for (int i = 0; i < num_sockets; i++) {
			if (poll_fds[i].revents & POLLIN) {
				if (poll_fds[i].fd == STDIN_FILENO) {
					fgets(buff, MAX_LEN - 1, stdin);
				
					if (strcmp(buff, "exit\n") == 0) {
						for (int j = 0; j < num_sockets; j++) {
							close(poll_fds[j].fd);
						}

						return 0;
					}
				} else if (poll_fds[i].fd == sock_tcp) {
					// Am primit o cerere de conexiune pe socketul de listen, pe care
					// o acceptam
					fout << "a gasit o conexiune\n";
					struct sockaddr_in cli_addr;
					socklen_t cli_len = sizeof(cli_addr);
					const int newsockfd =
						accept(sock_tcp, (struct sockaddr *)&cli_addr, &cli_len);
					DIE(newsockfd < 0, "accept");

					// Adaugam noul socket intors de accept() la multimea descriptorilor
					// de citire
					pollfd new_poll_fd;
					new_poll_fd.fd = newsockfd;
					new_poll_fd.events = POLLIN;

					// Add the new pollfd structure to the vector
					poll_fds.push_back(new_poll_fd);

					// Increment the number of sockets
					num_sockets++;

					// receive client ID from subscriber to print it
					char buffer[256];
					ssize_t bytes_received;
					struct chat_packet received_packet;
					int rc = recv_all(newsockfd, &received_packet, sizeof(received_packet));
		  			DIE(rc < 0, "recv");
										
					subscriber new_subscriber;
					size_t message_length = strlen(received_packet.message); // Find length of message
					new_subscriber.client_id = std::string(received_packet.message, message_length);

					// Check if there is a subscriber with the received client ID
					auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
						return sub.client_id == new_subscriber.client_id;
					});

					if (it != subscribers.end()) {
						if (it->connected == false) {
							it->connected = true;
							std::cout << "New client " << received_packet.message << " connected from " << port << ".\n";
						} else {
							close(newsockfd);
							std::cout << "Client " << it->client_id << " already connected." << "\n";
							continue;
						}
					} else {
						new_subscriber.connected = true;
						new_subscriber.subscribed_topics = std::set<std::string>();
						new_subscriber.sock_fd = newsockfd;
						subscribers.push_back(new_subscriber);
						std::cout << "New client " << received_packet.message << " connected from " << port << ".\n";
					}
				} else {
					struct chat_packet received_packet;
					int rc = recv_all(poll_fds[i].fd, &received_packet, sizeof(received_packet));

					if (rc == 0) {
						auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
							return sub.sock_fd == poll_fds[i].fd;
						});
						it->connected = false;
						std::cout << "Client " << it->client_id << " disconnected." << "\n";
						// fout << it->connected << "\n";
						// fout.flush();
						close(it->sock_fd);
						for (int j = i; j < num_sockets - 1; j++) {
							poll_fds[j] = poll_fds[j + 1];
						}
						num_sockets--;
						continue;
					}
          			DIE(rc < 0, "recv");


					std::string received_message(received_packet.message, received_packet.len);

					size_t space_pos = received_message.find(' ');
					
					// Extract the first part of the message before the space
					std::string command = received_message.substr(0, space_pos);

					// Extract the second part of the message after the space
					std::string topic;
					if (space_pos != std::string::npos) {
						topic = received_message.substr(space_pos + 1);
					}

					// fout << "command: " << command << "\n";\
					// fout.flush();
					// fout << "topic: " << topic << "\n";
					// fout.flush();

					auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
						return sub.sock_fd == poll_fds[i].fd;
					});

					
					if (it != subscribers.end() && command == "subscribe") {
						it->subscribed_topics.insert(topic);
					}

					// int k = 0;
					// for (auto topic : it->subscribed_topics) {
					// 	fout << "topic subscribed [" <<  k << "] " << topic << "\n";
					// 	fout.flush();
					// 	k++;
					// }
				}
			}
		}

	}

	// Close socket

	return 0;
}
