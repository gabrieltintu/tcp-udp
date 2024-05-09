// TINTU Gabriel-Claudiu 323CAb - 2023-2024

#include "common.hpp"

#include <sys/socket.h>
#include <sys/types.h>

int recv_all(int sockfd, void *buffer, size_t len)
{
	size_t bytes_received = 0;
	size_t bytes_remaining = len;
	char *buff = (char *)buffer;

	while (bytes_remaining) {
		size_t curr_bytes = recv(sockfd, buffer, bytes_remaining, 0);
		if (curr_bytes <= 0)
			break;

		bytes_received += curr_bytes;
		bytes_remaining -= curr_bytes;
		buff += curr_bytes;
	}

	return bytes_received;
}

int send_all(int sockfd, void *buffer, size_t len)
{
	size_t bytes_sent = 0;
	size_t bytes_remaining = len;
	char *buff = (char *)buffer;

	while (bytes_remaining) {
		size_t curr_bytes = send(sockfd, buffer, bytes_remaining, 0);
		if (curr_bytes <= 0)
			break;

		bytes_sent += curr_bytes;
		bytes_remaining -= curr_bytes;
		buff += curr_bytes;
	}

	return bytes_sent;
}