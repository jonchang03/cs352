/* Sample code from office hours. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netint/in.h>

#include "sock352.h"
#include "sock352lib.h"
#include "uthash.h"

int sock352_init(int port) {
	if (port == -1) {
		sock352_flag = SOCK352_SOCKETS;
		return 1;
	}
	/* create the root structure to hold the active connections */
	sock352_active_connections = (sock352_connection_t *) NULL;
	sock352_base_fd = 0;
	if (port > SOCK352_MAX_PORT) return SOCK352_FAILURE;

	sock352_recv_port = port;

	/* create a hash of socket file descriptors */

	/* create the main socket to receive UDP packets on */

	/* create the reader thread */

	/* create the timeout/manager thread */

	return SOCK352_SUCCESS;
}

int sock352_socket(int domain, int type, int protocol) {
	sock352_connection_t *new_sock;
	if (sock352_flag == SOCK352_SOCKETS) {
		return socket(AF_INET, SOCK_STREAM, 0);
	}

	if (domain != AF_CS352) {
		return SOCK352_FAILURE;
	}

	ir (type != SOCK_STREAM) {
		return SOCK352_FAILURE;
	}

	new_sock = malloc(sizeof(sock352_connection_t));
	if (new_sock == NULL) {
		return SOCK352_FAILURE;
	}

	/* create a new socket object and add it to the hash table */
	memset(new_sock, 0, sizeof(sock352_connections_t));
	sock352_base_fd += 1;
	new_sock->fd = sock352_base_fd;

	/* create a new socket object */
	return sock352_base_fd;
}

int sock352_bind(int fd, struct sockaddr_sock352 * addr, socklen_t len) {
	if (sock352_flag == SOCK352_SOCKETS) {
		struct sockaddr_in in_addr;
	
		in_addr.sin_family = AF_INET;
		in_addr.sin_addr.s_addr = INADDR_ANY;
		in_addr.sin_port = addr->sin_port;
		return bind(fd, (const struct sockaddr *) &in_addr, sizeof(in_addr));
	}
	return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n) {
	if (sock352_flag == SOCK352_SOCKETS) {
		return listen(fd, n);
	}
	return SOCK352_SUCCESS;
}

int sock352_accept(int fd, sockaddr_sock3532_t * addr, int *len) {
	int new_fd;
	new_fd = 0;
	if (sock352_flag == SOCK352_SOCKETS) {
		return accept(fd, (struct sockaddr *) addr, len);
	}

	return new_fd;
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
	if (sock352_flag == SOCK352_SOCKETS) {
		int r;
		struct sockaddr_in in_addr;

		in_addr.sin_family = AF_INET;
		in_addr.sin_addr.s_addr = addr->sin_addr.s_addr;
		in_addr.sin_port = addr->sin_port;
		r = connect(fd, (struct sockaddr *)&in_addr, sizeof(in_addr));
		return r;
	}
	return SOCK352_SUCCESS;
}

extern int sock352_close(int fd) {
	if (sock352_flag == SOCK352_SOCKETS) {
		return close(fd);
	}
	return SOCK352_SUCCESS;
}

int sock352_read(int fd, void *buf, int count) {
	if (sock352_flag == SOCK352_SOCKETS) {
		return read(fd, buf, count);
	}
	return count;
}

int sock352_write(int fd, void *buf, int count) {
	if (sock352_flag == SOCK352_SOCKETS) {
		return write(fd, buf, count);
	}
	return count;
}

int __sock352_input_packets() {
	
	/* get the next packet */

	/* figure out which connection structure this belongs to */

	/* queue the packet in right spot */

	/* if there is a blocking read on the data, wake the thread up */
	return 1;
}