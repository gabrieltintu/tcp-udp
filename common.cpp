#include "common.hpp"

#include <sys/socket.h>
#include <sys/types.h>

/*
    TODO 1.1: Rescrieți funcția de mai jos astfel încât ea să facă primirea
    a exact len octeți din buffer.
*/
int recv_all(int sockfd, void *buffer, size_t len) {

  size_t bytes_received = 0;
  size_t bytes_remaining = len;
  char *buff = (char *)buffer;
  /*

      while(bytes_remaining) {
          TODO: Make the magic happen
      }

  */

 	while (bytes_remaining) {
		size_t curr_bytes = recv(sockfd, buffer, bytes_remaining, 0);
		if (curr_bytes <= 0)
			break;

		bytes_received += curr_bytes;
		bytes_remaining -= curr_bytes;
		buff += curr_bytes;
	}

	return bytes_received;
	// return recv(sockfd, buffer, len, 0);
}

/*
    TODO 1.2: Rescrieți funcția de mai jos astfel încât ea să facă trimiterea
    a exact len octeți din buffer.
*/

int send_all(int sockfd, void *buffer, size_t len) {
  size_t bytes_sent = 0;
  size_t bytes_remaining = len;
  char *buff = (char *)buffer;
  /*
      while(bytes_remaining) {
          TODO: Make the magic happen
      }

  */

	while (bytes_remaining) {
		size_t curr_bytes = send(sockfd, buffer, bytes_remaining, 0);
		if (curr_bytes <= 0)
			break;

		bytes_sent += curr_bytes;
		bytes_remaining -= curr_bytes;
		buff += curr_bytes;
	}

	return bytes_sent;

//   return send(sockfd, buffer, len, 0);
}