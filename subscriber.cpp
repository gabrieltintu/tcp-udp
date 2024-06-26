// TINTU Gabriel-Claudiu 323CAb - 2023-2024

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include "helpers.hpp"
#include "common.hpp"

#define MAX_SOCK 2

/**
 * Send message to the server
 * Subscribe/Unsubscribe to/from topic X
 */
void send_to_server(char buff[], int sockfd)
{
	int rc;
	chat_packet send_message;
	strcpy(send_message.message, buff);
	send_message.len = strlen(send_message.message);
	rc = send_all(sockfd, &send_message, sizeof(send_message));
	DIE(rc < 0, "send");

	std::string input(send_message.message, send_message.len);

	size_t space_pos = input.find(' ');

	// extract command
	std::string command = input.substr(0, space_pos);

	// extract topic
	std::string topic;

	if (space_pos != std::string::npos)
		topic = input.substr(space_pos + 1);

	if (command == "subscribe")
		std::cout << "Subscribed to topic " << topic;
	else
		std::cout << "Unsubscribed from topic " << topic;
}

/*
 * Receive the message sent by UDP clients through the server
 */
bool recv_from_server(pollfd poll_fds[], int sockfd)
{
	tcp_message message;
	uint16_t actual_size = 0;
	int rc;

	rc = recv(sockfd, &actual_size, sizeof(actual_size), 0);
	DIE(rc < 0, "receiving size");

	rc = recv_all(sockfd, &message, actual_size);

	if (rc == 0) {
		for (int i = 0; i < MAX_SOCK; i++)
			close(poll_fds[i].fd);

		return true;
	}

	DIE(rc < 0, "receiving message");

	std::cout << message.ip << ":" << message.port << " - " << message.topic;
	std::cout << " - " << message.data_type << " - " << message.content << "\n";
	return false;
}

int main(int argc, char *argv[]) {
	// check arg
	if (argc != 4) {
		std::cerr << "Usage: " << argv[0] << " <ID_CLIENT> <IP_SERVER> <PORT_SERVER>\n";
		return 1;
	}

	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	pollfd poll_fds[MAX_SOCK];

	std::string client_id = argv[1];
	std::string server_ip = argv[2];
	std::string port_str = argv[3];

	int port = std::atoi(argv[3]);
	int rc;
	// Create TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "sockfd");

	sockaddr_in server_addr;
	socklen_t socket_len = sizeof(sockaddr_in);

	memset(&server_addr, 0, socket_len);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

	// connect to the server
	rc = connect(sockfd, (sockaddr *)&server_addr, sizeof(server_addr));
	DIE(rc < 0, "connect");

	poll_fds[0].fd = sockfd;
	poll_fds[0].events = POLLIN;

	poll_fds[1].fd = STDIN_FILENO;
	poll_fds[1].events = POLLIN;

	int num_sockets = 2;

	// send client data to the server
	chat_packet sent_packet;
	std::string client_data = client_id + " " + server_ip + ":" + port_str;
	sent_packet.len = client_data.size() + 1;
	strcpy(sent_packet.message, client_data.c_str());

	rc = send_all(sockfd, &sent_packet, sizeof(sent_packet));
	DIE(rc < 0, "send");

	// Main loop to receive commands from user
	while (true) {
		char buff[MAX_LEN];
		rc = poll(poll_fds, num_sockets, -1);
		DIE(rc < 0, "poll");

		if (poll_fds[0].revents & POLLIN) {
			bool close = recv_from_server(poll_fds, sockfd);
			if (close)
				break;
		} else if (poll_fds[1].revents & POLLIN) {
			fgets(buff, MAX_LEN - 1, stdin);

			if (strcmp(buff, "exit\n") == 0) {
				for (int i = 0; i < num_sockets; i++)
					close(poll_fds[i].fd);

				return 0;
			}

			send_to_server(buff, sockfd);
		}
	}

	return 0;
}
