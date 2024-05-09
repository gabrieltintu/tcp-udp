#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>
#include <string>

int send_all(int sockfd, void *buff, size_t len);
int recv_all(int sockfd, void *buff, size_t len);

#define MAX_LEN 100
#define MAX_TOPIC 51
#define MAX_TYPE 11
#define MAX_CONTENT 1501
#define MAX_UDP_LEN 1584

struct chat_packet {
	uint16_t len;
	char message[MAX_LEN];
};

struct tcp_message {
	char ip[16];
	int port;
	char topic[MAX_TOPIC];
	char data_type[MAX_TYPE];
	char content[MAX_CONTENT];
};

#endif
