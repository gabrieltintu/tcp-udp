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
#include <netinet/tcp.h>
#include <poll.h>
#include <set>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "helpers.h"
#include "common.hpp"

// using namespace std;

std::ofstream fout("file_server.out");

struct subscriber {
	bool connected;
	std::set<std::string> subscribed_topics;
	int sock_fd;
	std::string client_id;
};

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

    if (!word.empty()) {
        result.push_back(word);
    }

	return result;
}

bool check_wildcards(std::string wc_topic, std::string topic)
{
	std::vector<std::string> wc_t_arr = split_topic(wc_topic);
	std::vector<std::string> t_arr = split_topic(topic);

	int i = 0, j = 0;

	while (i != wc_t_arr.size() && j != t_arr.size()) {
		if (wc_t_arr[i] == "+") {
			i++;
			j++;
			continue;
		}

		if (wc_t_arr[i] == "*") {
			if (i + 1 == wc_t_arr.size()) {
				return true;
			}
			
			j++;
			if (j == t_arr.size())
				return false;

			if (wc_t_arr[i + 1] != t_arr[j])
				continue;
			
			i++;
			continue;
		}

		if (wc_t_arr[i] != t_arr[j])
			return false;

		i++;
		j++;
	}

	if (i != wc_t_arr.size() || j != t_arr.size())
		return false;
	return true;

}


void build_client_message(tcp_message& message,char buff[])
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

			// Create a stringstream object
			std::stringstream ss;

			// Set the precision of the float value
			ss.precision(power);

			// Write the float value to the stringstream
    		ss << std::fixed << std::setprecision(power) << content;

			// Get the string representation from the stringstream and store it in message.content
			std::string contentStr = ss.str();
			sprintf(message.content, "%s", contentStr.c_str());

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




int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	// check arg
	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <PORT>\n";
		return EXIT_FAILURE;
	}

	std::vector<pollfd> poll_fds;
	std::vector<subscriber> subscribers;

	struct sockaddr_in serv_addr, cli_addr;
	socklen_t cli_len = sizeof(cli_addr);
	socklen_t socket_len = sizeof(struct sockaddr_in);

	int rc;

	// set port
	uint16_t port;
	port = atoi(argv[1]);
	fout << "server: " << port << "\n";
	fout.flush();

	// create TCP socket
	int sock_tcp, sock_udp;

	// creare socket pt TCP + bind + listen
	sock_tcp = socket(AF_INET, SOCK_STREAM, 0);

	// make socket address reusable
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
	rc = listen(sock_tcp, SOMAXCONN);
	DIE(rc < 0, "eroare listen - udp\n");

	// Adaugam noul file descriptor (socketul pe care se asculta conexiuni) in
	// multimea poll_fds
	pollfd listen_poll_fd;
	listen_poll_fd.fd = sock_tcp;
	listen_poll_fd.events = POLLIN;

	// Push back the listen pollfd structure into the vector
	poll_fds.push_back(listen_poll_fd);

	sock_udp = socket(AF_INET, SOCK_DGRAM, 0);

	rc = bind(sock_udp, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "eroare bind - tcp\n");

	pollfd listen_poll_fd_udp;
	listen_poll_fd_udp.fd = sock_udp;
	listen_poll_fd_udp.events = POLLIN;

	poll_fds.push_back(listen_poll_fd_udp);

	pollfd stdin_poll_fd;
	stdin_poll_fd.fd = STDIN_FILENO;
	stdin_poll_fd.events = POLLIN;
	poll_fds.push_back(stdin_poll_fd);
	
	int num_sockets = 3;

	while (1) {
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
					
					const int newsockfd =
						accept(sock_tcp, (struct sockaddr *)&cli_addr, &cli_len);
					DIE(newsockfd < 0, "accept");

					int nagle = 1;
                    rc = setsockopt(newsockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&nagle, sizeof(int));
                    DIE(rc < 0, "eroare Nagle");


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
					rc = recv_all(newsockfd, &received_packet, sizeof(received_packet));
		  			DIE(rc < 0, "recv");
					std::string client_data(received_packet.message);		
					subscriber new_subscriber;

					size_t space_pos = client_data.find(' ');
					if (space_pos == std::string::npos) {
						std::cerr << "Error: No space found in input string." << std::endl;
						return 1;
					}
					// Extract ID_CLIENT
					std::string id_client = client_data.substr(0, space_pos);
					std::string ip_port = client_data.substr(space_pos + 1);
					
					new_subscriber.client_id = id_client;

					// Check if there is a subscriber with the received client ID
					auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
						return sub.client_id == new_subscriber.client_id;
					});

					if (it != subscribers.end()) {
						if (it->connected == false) {
							it->connected = true;
							it->sock_fd = newsockfd;
							std::cout << "New client " << id_client << " connected from " << ip_port << ".\n";
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
						std::cout << "New client " << id_client << " connected from " << ip_port << ".\n";
					}
				} else if (poll_fds[i].fd == sock_udp) {
				
					char msg_buff[MAX_UDP_LEN];
					rc = recvfrom(sock_udp, &msg_buff, sizeof(msg_buff), 0, (struct sockaddr *)&cli_addr, &cli_len);
					// udp_message *recv_message = (udp_message *)msg_buff;
					DIE(rc < 0, "receive udp");
					tcp_message message;
					build_client_message(message, msg_buff);
					strcpy(message.ip, inet_ntoa(cli_addr.sin_addr));
					message.port = port;
					strncpy(message.topic, msg_buff, MAX_TOPIC);
					message.topic[MAX_TOPIC - 1] = '\0';
					for (auto sub : subscribers) {
						bool to_send = false;

						if (sub.connected == false)
							continue;

						for (auto sub_topic : sub.subscribed_topics) {
							std::string topic(message.topic);
								
							to_send = check_wildcards(sub_topic, topic);

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

				} else {
					struct chat_packet received_packet;
					rc = recv_all(poll_fds[i].fd, &received_packet, sizeof(received_packet));

					if (rc == 0) {
						auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
							return sub.sock_fd == poll_fds[i].fd;
						});
						it->connected = false;
						std::cout << "Client " << it->client_id << " disconnected." << "\n";
						close(it->sock_fd);
						for (int j = i; j < num_sockets - 1; j++) {
							poll_fds[j] = poll_fds[j + 1];
						}
						num_sockets--;
						i--;
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

					auto it = std::find_if(subscribers.begin(), subscribers.end(), [&](const subscriber& sub) {
						return sub.sock_fd == poll_fds[i].fd;
					});

					
					if (it != subscribers.end() && command == "subscribe") {
						it->subscribed_topics.insert(topic);
					}


					if (it != subscribers.end() && command == "unsubscribe") {
						it->subscribed_topics.erase(topic);
					}

				
				}
			}
		}
	}

	// Close socket

	return 0;
}
