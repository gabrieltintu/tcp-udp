#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fstream>
#include <poll.h>
#include "helpers.h"
#include "common.hpp"

std::ofstream fout("file_subscriber.out");


#define MAX_LEN 100



int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	if (argc != 4) {
		std::cerr << "Usage: " << argv[0] << " <ID_CLIENT> <IP_SERVER> <PORT_SERVER>\n";
		return EXIT_FAILURE;
	}

	struct pollfd poll_fds[2];
	// Parse command-line arguments
	std::string clientId = argv[1];
	std::string serverIp = argv[2];
	int serverPort = std::atoi(argv[3]);
	int rc;
	// Create TCP socket
	int tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcpSocket == -1) {
		std::cerr << "Error creating TCP socket\n";
		return EXIT_FAILURE;
	}

	// Initialize server address structure
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(serverPort);
	inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);
	fout << "client id: " << clientId << "\n";
	// Connect to the server
	rc = connect(tcpSocket, (struct sockaddr*) &serverAddr, sizeof(serverAddr));
	DIE(rc < 0, "connect");
	
	poll_fds[0].fd = tcpSocket; // pt server
	poll_fds[0].events = POLLIN;


	poll_fds[1].fd = 0; // pt stdin
	poll_fds[1].events = POLLIN;

	int num_sockets = 2;

	struct chat_packet sent_packet;
	struct chat_packet recv_packet;

	sent_packet.len = clientId.size() + 1;
	strcpy(sent_packet.message, clientId.c_str());

	rc = send_all(tcpSocket, &sent_packet, sizeof(sent_packet));    
	DIE(rc < 0, "send");

	// Main loop to receive commands from user
	while (true) {
		char buff[MAX_LEN];
		rc = poll(poll_fds, num_sockets, -1);
		DIE(rc < 0, "poll");
		// if (poll_fds[0].revents & POLLIN) {
		// 	if (recv_all(tcpSocket, &recv_packet, sizeof(recv_packet)) == 0) {
		// 		close(tcpSocket);
		// 		return 0;
		// 	}
		// }

		for (int i = 0; i < num_sockets; i++) {
			if (poll_fds[i].revents & POLLIN) {
				if (poll_fds[i].fd == tcpSocket) {
					struct tcp_message message;
					rc = recv_all(tcpSocket, &message, sizeof(message));
					if (rc == 0) {
						fout << "nu e bn\n";
						close(tcpSocket);
						return 0;
					}
					// fout << rc;
					// fout.flush();
					std::cout << message.ip << ":" << message.port << " - " << message.topic << " - " << message.data_type << " - " << message.content << "\n";
					fflush(stdout);
					// fout << message.ip << ":" << message.port << " - " << message.topic << " - " << message.data_type << " - " << message.content << "\n";
					// fout.flush();
				} else if (poll_fds[i].fd == 0) {
					fgets(buff, MAX_LEN - 1, stdin);
				
					if (strcmp(buff, "exit\n") == 0) {
						// struct chat_packet send_subscribe;
						// strcpy(send_subscribe.message, buff);
						// send_subscribe.len = strlen(send_subscribe.message);
						// rc = send_all(tcpSocket, &send_subscribe, sizeof(send_subscribe));
						// DIE(rc < 0, "send");

						for (int j = 0; j < num_sockets; j++) {
							close(poll_fds[i].fd);
						}
						return 0;
					} else if (strncmp(buff, "subscribe", 9) == 0) {
						struct chat_packet send_subscribe;
						strcpy(send_subscribe.message, buff);
						send_subscribe.len = strlen(send_subscribe.message);
						rc = send_all(tcpSocket, &send_subscribe, sizeof(send_subscribe));
						DIE(rc < 0, "send");

						std::string command(send_subscribe.message, send_subscribe.len);

						size_t space_pos = command.find(' ');
						
						// Extract the first part of the message before the space
						std::string sub = command.substr(0, space_pos);

						// Extract the second part of the message after the space
						std::string topic;
						if (space_pos != std::string::npos) {
							topic = command.substr(space_pos + 1);
						}
						// fout << "topic " << topic << "\n";
						// fout.flush();

						std::cout << "Subscribed to topic " << topic;
						// fout << "Subscribed to topic " << topic << "\n";
						// fout.flush();
					} else if (strncmp(buff, "unsubscribe", 11) == 0) {
						struct chat_packet send_unsubscribe;
						strcpy(send_unsubscribe.message, buff);
						send_unsubscribe.len = strlen(send_unsubscribe.message);
						rc = send_all(tcpSocket, &send_unsubscribe, sizeof(send_unsubscribe));
						DIE(rc < 0, "send");

						std::string command(send_unsubscribe.message, send_unsubscribe.len);

						size_t space_pos = command.find(' ');
						
						// Extract the first part of the message before the space
						std::string unsub = command.substr(0, space_pos);

						// Extract the second part of the message after the space
						std::string topic;
						if (space_pos != std::string::npos) {
							topic = command.substr(space_pos + 1);
						}

						std::cout << "Unsubscribed from topic " << topic;

					}
				}
			}
		}
	}

	return 0;
}
