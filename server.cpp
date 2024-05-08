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





// struct message_to_client {};

struct subscriber {
	bool connected;
	std::set<std::string> subscribed_topics;
	int sock_fd;
	std::string client_id;
};

std::vector<std::string> split_topic(std::string str) {
	std::vector<std::string> result;
    std::string word;
	// if (word[word.size()] == '\n') {
	// 	word[word.size()] = '\0';
	// }
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
	fout << "a intrat iun check wc\n";
	int i = 0, j = 0;
	fout << "wc size: " << wc_t_arr.size() << "\n";
	fout << " size: " << t_arr.size() << "\n";
	while (i != wc_t_arr.size() && j != t_arr.size()) {
		fout << "wc_t_arr[" << i << "]: " << wc_t_arr[i] << "\n";
		fout.flush();
		fout << "t_arr[" << j << "]: " << t_arr[j] << "\n";
		fout.flush();
		if (wc_t_arr[i] == "+") {
			i++;
			j++;
			fout << "cazul cu +\n";
			fout.flush();
			continue;
		}

		if (wc_t_arr[i] == "*") {
			if (i + 1 == wc_t_arr.size()) {
				fout << "suge o\n";
				fout.flush();
				return true;
			}
			
			j++;
			if (j == t_arr.size()) {
				fout << "pula mea 1\n";
				fout.flush();
				return false;
			}

			if (wc_t_arr[i + 1] != t_arr[j])
				continue;
			
			fout << "i " << i << "\n";
			fout.flush();
			fout << "j " << j << "\n";
			fout.flush();
			i++;
			continue;
		}

		if (wc_t_arr[i] != t_arr[j]) {
			fout << "pula mea 2\n";
			fout.flush();
			return false;
		}

		i++;
		j++;
	}

	if (i != wc_t_arr.size() || j != t_arr.size())
		return false;
	fout << "TRUE?????\n";
	fout.flush();
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
			// fout << "sgn: " << sgn << "\n";
			// fout.flush();
			// fout << "content: " << sgn_content << "\n";
			// fout.flush();
			// strncpy(message.data_type, "INT", MAX_TYPE);
			// message.data_type[3] = '\0';
			sprintf(message.data_type, "INT");

			sprintf(message.content, "%d", content);

			break;
		}
		case 1: {
			double content = ntohs(*(uint16_t *)(buff + MAX_TOPIC));
			content /= 100;
			// fout << "content: " << content << "\n";
			// fout.flush();
			// strncpy(message.data_type, "REAL", MAX_TYPE);
			// message.data_type[4] = '\0';
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

			// strncpy(message.data_type, "FLOAT", MAX_TYPE);
			// message.data_type[5] = '\0';
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

			// strncpy(message.data_type, "STRING", MAX_TYPE);
			// message.data_type[6] = '\0';

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

	struct sockaddr_in cli_addr;
	socklen_t cli_len = sizeof(cli_addr);

	int num_sockets = 1;
	int rc;
	// set port
	uint16_t port;
	rc = sscanf(argv[1], "%hu", &port);
	DIE(rc != 1, "Given port is invalid");
	fout << "server: " << port << "\n";
	fout.flush();

	// create TCP socket
	int sock_tcp, sock_udp;
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

	sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
	const int enable2 = 1;
	if (setsockopt(sock_udp, SOL_SOCKET, SO_REUSEADDR, &enable2, sizeof(int)) < 0)
		perror("setsockopt(SO_REUSEADDR) failed");

	rc = bind(sock_udp, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	DIE(rc < 0, "eroare bind - tcp\n");
	


	pollfd listen_poll_fd_udp;
	listen_poll_fd_udp.fd = sock_udp;
	listen_poll_fd_udp.events = POLLIN;

	poll_fds.push_back(listen_poll_fd_udp);
	num_sockets++;

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
					
					const int newsockfd =
						accept(sock_tcp, (struct sockaddr *)&cli_addr, &cli_len);
					DIE(newsockfd < 0, "accept");

					int neagle = 1;
                    rc = setsockopt(newsockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&neagle, sizeof(int));
                    DIE(rc < 0, "eroare Neagle");


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
							it->sock_fd = newsockfd;
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
						for (auto sub_topic : sub.subscribed_topics) {
							std::string topic(message.topic);
							
							if (sub_topic.find("+") != std::string::npos || sub_topic.find("*") != std::string::npos) {
								to_send = check_wildcards(sub_topic, topic);
								fout << "to send in if: " << to_send << "\n";
								fout.flush();
							}
							fout << "to send: " << to_send << "\n";
							fout.flush();
							if ((to_send || strncmp(message.topic, sub_topic.c_str(), strlen(message.topic)) == 0) && sub.connected == true) {
								rc = send_all(sub.sock_fd, &message, sizeof(message));
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
						// fout << it->connected << "\n";
						// fout.flush();
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


					if (it != subscribers.end() && command == "unsubscribe") {
						it->subscribed_topics.erase(topic);
					}

					int k = 0;
					for (auto topic : it->subscribed_topics) {
						fout << "topic subscribed [" <<  k << "] " << topic << "\n";
						fout.flush();
						k++;
					}
				}
			}
		}
	}

	// Close socket

	return 0;
}
