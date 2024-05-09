// TINTU Gabriel-Claudiu 323CAb - 2023-2024

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <vector>
#include <set>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "helpers.hpp"
#include "common.hpp"

struct subscriber {
	bool connected;
	std::set<std::string> subscribed_topics;
	int sock_fd;
	std::string client_id;
};

/**
 * Split the topic into a vector of strings.
 */
std::vector<std::string> split_topic(std::string str) {
	std::vector<std::string> result;
	std::string word;

	for (char ch : str) {
		if (ch != '/' && ch != '\n') {
			word += ch;

		} else {
			result.push_back(word);
			word.clear();
		}
	}

	if (!word.empty())
		result.push_back(word);

	return result;
}

/**
 * Check if the topic received matches the subscribed one.
 */
bool check_topic(std::string recv_topic, std::string topic)
{
	if (recv_topic == topic)
		return true;

	std::vector<std::string> recv_t_arr = split_topic(recv_topic);
	std::vector<std::string> t_arr = split_topic(topic);

	unsigned long int i = 0, j = 0;

	while (i != recv_t_arr.size() && j != t_arr.size()) {
		if (recv_t_arr[i] == "+") {
			i++;
			j++;
			continue;
		}

		if (recv_t_arr[i] == "*") {
			if (i + 1 == recv_t_arr.size()) {
				return true;
			}

			j++;
			if (j == t_arr.size())
				return false;

			if (recv_t_arr[i + 1] != t_arr[j])
				continue;

			i++;
			continue;
		}

		if (recv_t_arr[i] != t_arr[j])
			return false;

		i++;
		j++;
	}

	if (i != recv_t_arr.size() || j != t_arr.size())
		return false;

	return true;
}

/**
 * Build the message to send to the TCP clients
 * with the received buffer from UDP clients.
 */
void build_client_message(tcp_message& message, char buff[])
{
	switch (buff[MAX_TOPIC - 1]) {
		case 0: {
			int sgn = (int)buff[MAX_TOPIC];
			uint32_t unsgn_content = ntohl(*(uint32_t *)(buff + MAX_TOPIC + 1));
			int32_t content;
			content = (int32_t)unsgn_content;
			if (sgn == 1)
				content = -content;

			sprintf(message.data_type, "INT");

			sprintf(message.content, "%d", content);

			break;
		}
		case 1: {
			double content = ntohs(*(uint16_t *)(buff + MAX_TOPIC));
			content /= 100;

			sprintf(message.data_type, "SHORT_REAL");

			sprintf(message.content, "%.2f", content);
			break;
		}
		case 2: {
			int sgn = (int)buff[MAX_TOPIC];
			uint32_t nr = ntohl(*(uint32_t *)(buff + MAX_TOPIC + 1));
			uint8_t power = *(uint8_t *)(buff + MAX_TOPIC + 1 + sizeof(uint32_t));
			float content = nr / pow(10, power);

			if (sgn == 1)
				content = -content;

			sprintf(message.data_type, "FLOAT");

			// create a stringstream
			std::stringstream ss;

			// write the float value to the stringstream
			ss << std::fixed << std::setprecision(power) << content;

			// get the string from the stringstream
			std::string content_str = ss.str();
			sprintf(message.content, "%s", content_str.c_str());

			break;
		}
		case 3: {
			char content[MAX_CONTENT];
			strcpy(content, buff + MAX_TOPIC);

			sprintf(message.data_type, "STRING");

			sprintf(message.content, "%s", content);
			break;
		}
	}
}

/**
 * Function to accept a new connection/refuse it if a client
 * with the same ID already exists.
 */
void handle_new_connection(std::vector<pollfd>& poll_fds,
		std::vector<subscriber>& subscribers, int listenfd, int& num_sockets)
{
	sockaddr_in cli_addr;
	socklen_t cli_len = sizeof(cli_addr);

	const int new_sock_fd = accept(listenfd, (sockaddr *)&cli_addr, &cli_len);
	DIE(new_sock_fd < 0, "accept");

	int nagle = 1;
	int rc;
	rc = setsockopt(new_sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&nagle, sizeof(int));
	DIE(rc < 0, "eroare Nagle");

	// add the new socket returned by accept() to poll_fds
	pollfd new_poll_fd;
	new_poll_fd.fd = new_sock_fd;
	new_poll_fd.events = POLLIN;
	poll_fds.push_back(new_poll_fd);

	num_sockets++;

	// receive client ID from subscriber to print it
	chat_packet received_packet;
	rc = recv_all(new_sock_fd, &received_packet, sizeof(received_packet));
	DIE(rc < 0, "recv");
	std::string client_data(received_packet.message);

	subscriber new_subscriber;

	size_t space_pos = client_data.find(' ');
	DIE(space_pos == std::string::npos, "no space found");

	std::string id_client = client_data.substr(0, space_pos);
	std::string ip_port = client_data.substr(space_pos + 1);

	new_subscriber.client_id = id_client;

	// check if there is a subscriber with the received client ID
	auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
		return sub.client_id == new_subscriber.client_id;
	});

	if (it != subscribers.end()) {
		if (!it->connected) {
			it->connected = true;
			it->sock_fd = new_sock_fd;
			std::cout << "New client " << id_client << " connected from " << ip_port << ".\n";
		} else {
			poll_fds.pop_back();
			close(new_sock_fd);
			std::cout << "Client " << it->client_id << " already connected." << "\n";
			return;
		}
	} else {
		new_subscriber.connected = true;
		new_subscriber.subscribed_topics = std::set<std::string>();
		new_subscriber.sock_fd = new_sock_fd;
		subscribers.push_back(new_subscriber);
		std::cout << "New client " << id_client << " connected from " << ip_port << ".\n";
	}
}

/**
 * Receive the message from UDP clients and send it to TCP clients
 * subscribed to the topic.
 */
void handle_udp_messages(std::vector<subscriber> subscribers, int sock_udp, int port)
{
	sockaddr_in cli_addr;
	socklen_t cli_len = sizeof(cli_addr);
	int rc;
	char msg_buff[MAX_UDP_LEN];

	// receive the message from UDP client
	rc = recvfrom(sock_udp, &msg_buff, sizeof(msg_buff), 0, (sockaddr *)&cli_addr, &cli_len);
	DIE(rc < 0, "receive udp");

	tcp_message message;

	build_client_message(message, msg_buff);

	strcpy(message.ip, inet_ntoa(cli_addr.sin_addr));
	message.port = port;
	strncpy(message.topic, msg_buff, MAX_TOPIC);
	message.topic[MAX_TOPIC - 1] = '\0';

	// send the message to all subscribed clients to the topic
	for (auto sub : subscribers) {
		bool to_send = false;

		if (!sub.connected)
			continue;

		for (auto sub_topic : sub.subscribed_topics) {
			std::string topic(message.topic);

			to_send = check_topic(sub_topic, topic);

			if (to_send) {
				uint16_t actual_size = MAX_UDP_LEN - MAX_CONTENT + strlen(message.content);
				message.content[MAX_UDP_LEN - MAX_CONTENT + strlen(message.content)] = '\0';

				rc = send(sub.sock_fd, &actual_size, sizeof(actual_size), 0);
				DIE(rc < 0, "send size");

				rc = send_all(sub.sock_fd, &message, actual_size);
				DIE(rc < 0, "send from udp to subs");

				break;
			}
		}
	}
}

/**
 * Handle the messages received from the TCP clients.
 */
void handle_tcp_messages(std::vector<pollfd>& poll_fds,
				std::vector<subscriber>& subscribers, int& num_sockets, int& i)
{
	chat_packet received_packet;
	int rc;

	rc = recv_all(poll_fds[i].fd, &received_packet, sizeof(received_packet));

	// disconnect the client
	if (rc == 0) {
		auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
			return sub.sock_fd == poll_fds[i].fd;
		});

		it->connected = false;

		std::cout << "Client " << it->client_id << " disconnected." << "\n";
		close(it->sock_fd);

		for (int j = i; j < num_sockets - 1; j++)
			poll_fds[j] = poll_fds[j + 1];

		poll_fds.pop_back();
		num_sockets--;
		i--;

		return;
	}

	DIE(rc < 0, "recv");

	// message is subscribe/unsubscribe
	std::string received_message(received_packet.message, received_packet.len);

	size_t space_pos = received_message.find(' ');

	// extract the command
	std::string command = received_message.substr(0, space_pos);

	// extract the topic
	std::string topic;
	if (space_pos != std::string::npos)
		topic = received_message.substr(space_pos + 1);

	auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
		return sub.sock_fd == poll_fds[i].fd;
	});

	if (it != subscribers.end() && command == "subscribe")
		it->subscribed_topics.insert(topic);

	if (it != subscribers.end() && command == "unsubscribe")
		it->subscribed_topics.erase(topic);
}

int main(int argc, char *argv[]) {
	// check arg
	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <PORT>\n";
		return EXIT_FAILURE;
	}

	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	std::vector<pollfd> poll_fds(3);
	std::vector<subscriber> subscribers;

	sockaddr_in serv_addr;
	socklen_t socket_len = sizeof(sockaddr_in);

	int rc;
	int port;

	port = atoi(argv[1]);

	// create TCP socket
	int listenfd, sock_udp;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(listenfd < 0, "listenfd");

	// make socket address reusable
	const int enable = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		std::cerr << "setsockopt(SO_REUSEADDR) failed";

	memset(&serv_addr, 0, socket_len);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	rc = bind(listenfd, (sockaddr *) &serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "bind");
	rc = listen(listenfd, SOMAXCONN);
	DIE(rc < 0, "listen");

	poll_fds[0].fd = listenfd;
	poll_fds[0].events = POLLIN;

	// create UDP socket
	sock_udp = socket(AF_INET, SOCK_DGRAM, 0);

	rc = bind(sock_udp, (sockaddr *)&serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "bind udp");

	poll_fds[1].fd = sock_udp;
	poll_fds[1].events = POLLIN;

	poll_fds[2].fd = STDIN_FILENO;
	poll_fds[2].events = POLLIN;

	int num_sockets = 3;

	while (1) {
		char buff[MAX_LEN];

		rc = poll(poll_fds.data(), poll_fds.size(), -1);
		DIE(rc < 0, "poll");

		for (int i = 0; i < num_sockets; i++) {
			if (poll_fds[i].revents & POLLIN) {
				if (poll_fds[i].fd == STDIN_FILENO) {
					// received from stdin
					fgets(buff, MAX_LEN - 1, stdin);

					if (strcmp(buff, "exit\n") == 0) {
						for (int j = 0; j < num_sockets; j++)
							close(poll_fds[j].fd);

						return 0;
					}
				} else if (poll_fds[i].fd == listenfd) {
					handle_new_connection(poll_fds, subscribers, listenfd, num_sockets);
				} else if (poll_fds[i].fd == sock_udp) {
					handle_udp_messages(subscribers, sock_udp, port);
				} else {
					handle_tcp_messages(poll_fds, subscribers, num_sockets, i);
				}
			}
		}
	}

	return 0;
}
