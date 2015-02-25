/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sock352lib.h>
#include <sock352.h>
#include <uthash.h>

int sock352_init(int udp_port)
{
  if (udp_port != 0) {
    return SOCK352_FAILURE;
  } else {
    /* timeout thread */
    /* global structure for all connections */ 
    _GLOABAL.active_connections = (sock352_connection_t *) NULL;
    _GLOABAL.sock352_base_fd = 0;
    /* socket port numbers to use */
    _GLOABAL.sock352_recv_port = SOCK352_DEFAULT_UDP_PORT;
    return SOCK352_SUCCESS;
  }  
}

int sock352_socket(int domain, int type, int protocol)
{
  if (domain != AF_CS352) {
    return SOCK352_FAILURE;
    
  }
  if (type != SOCK_STREAM) {
    return SOCK352_FAILURE;
  }
  return socket(domain, type, protocol);
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
	struct sockaddr_in tmpaddr;
	memset((char *)&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = AF_INET;
	tmpaddr.sin_port = addr->sin_port;
	tmpaddr.sin_addr.s_addr = addr->sin_addr.s_addr;
	return bind(fd, (struct sockaddr *)&tmpaddr, sizeof(tmpaddr));
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
	/*
		-create a UDP connection packet
		-set up a sequence number
		-send a SYN packet sendto()

		-extract (ACK) numbers
		-create empty list of fragments (send and receive)
		-start timeout thread (What if packets get dropped?)
		Loop pattern:
			-Lock the connection (pthread_mutex_lock())
			-scan the transmit fragment list for timeouts
			-resend expired fragments
			-unlock
			-call receive packets function (non-blocking)
				(or have a separate receiver thread)
			-sleep for the timeout value
		-return from connect() call
	*/
}

int sock352_listen(int fd, int n)
{
  return listen(fd, n);
}
int sock352_accept(int fd, sockaddr_sock352_t *addr, int *len)
{
	/* 
		-wait for a connection packet recfrom()

		-set up sequence and acknowledgement numbers
		-return a SYS/ACK flagged packet
		-create empty lists of fragments (receive and send)

		- return from accept() call
	*/
}

int sock352_close(int fd)
{
  return close(fd);
}
int sock352_read(int fd, void *buf, int count)
{
  return read(fd, buf, count);

  /*
		-Block waiting for a UDP packet
		Receive packet function:
			-Lock the connection
			-Update transmit list with new ack#
			-Find the place on the recv fragment list
			-Insert the fragment
			-Find the lowest # fragment
			-send an ACK with the highest sequence
			-Copy the data from the read pointer
			-unlock
			-Return from the read call.
  */
}
int sock352_write(int fd, void *buf, int count)
{
  return write(fd, buf, count);

  /*
  	-lock the connection
  	-create a new fragment
  	-create a new packet header for this fragment
  	-add it to the transmit list
  	-send the header + data
  	-record the time sent
  	-unlock the connection
  */
}
