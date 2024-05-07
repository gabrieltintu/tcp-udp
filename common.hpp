#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>
#include <string>
int send_all(int sockfd, void *buff, size_t len);
int recv_all(int sockfd, void *buff, size_t len);

/* Dimensiunea maxima a mesajului */
#define MSG_MAXSIZE 1024
#define MAX_LEN 100
#define MAX_TOPIC 51
#define MAX_TYPE 11
#define MAX_CONTENT 1501
#define MAX_UDP_LEN 1552

struct chat_packet {
  uint16_t len;
  char message[MSG_MAXSIZE + 1];
};

struct tcp_message {
	char ip[16];
	int port;
	char topic[MAX_TOPIC];
	char data_type[MAX_TYPE];
	char content[MAX_CONTENT];
};

#endif
