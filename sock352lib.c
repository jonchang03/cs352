/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sock352lib.h"
#include <time.h>

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

    /* create a connection*/
    sock352_connection_t * conn = malloc(sizeof(sock352_connection_t));
    memset(conn, 0, sizeof(sock352_connection_t));
    conn->state = CLOSED;
    HASH_ADD_INT(_GLOABAL.active_connections, sock352_fd, conn);
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
  struct sockaddr_in addr_in;
  memset((char *)&addr_in, 0, sizeof(addr_in));
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = addr->sin_port;
  addr_in.sin_addr.s_addr = addr->sin_addr.s_addr;
  return bind(fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  /*		-extract (ACK) numbers
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
  sock352_fragment_t *syn = malloc(sizeof(sock352_fragment_t));
  memset(syn, 0, sizeof(sock352_fragment_t));
  srand((unsigned int)(time(NULL)));
  syn->header.sequence_no = rand();
  syn->header.flags = SOCK352_SYN;
  struct sockaddr_in servaddr;
  memset((char *)&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = addr->sin_port;
  servaddr.sin_addr.s_addr = addr->sin_addr.s_addr;
  sendto(fd, syn, sizeof(syn), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
  _GLOABAL.active_connections
  sock352_fragment_t *ack = malloc(sizeof(sock352_fragment_t));
  memset(ack, 0, sizeof(sock352_fragment_t));
  recvfrom(fd, ack, sizeof(ack), 0, (struct sockaddr *)&servaddr, &sizeof(servaddr));;
  
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
