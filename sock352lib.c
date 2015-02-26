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
  int fd = socket(domain, type, protocol);
  sock352_connection_t * conn = malloc(sizeof(sock352_connection_t));
  memset(conn, 0, sizeof(sock352_connection_t));
  conn->state = CLOSED;
  conn->sock352_fd = fd;
  HASH_ADD_INT(_GLOABAL.active_connections, sock352_fd, conn);
  return fd;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  /* find the connection in hash table */
  sock352_connection_t * conn;
  HASH_FIND_INT(_GLOABAL.active_connections, &fd, conn);

  /* set up the source address and port in this connection */
  conn->src_addr = addr->sin_addr;
  conn->src_port = addr->sin_port;
  
  return bind(fd, (struct sockaddr *)&addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  /* find the connection in hash table */
  sock352_connection_t * conn;
  HASH_FIND_INT(_GLOABAL.active_connections, &fd, conn);

  /* set up the destination address and port in this connection */
  conn->dest_addr = addr->sin_addr;
  conn->dest_port = addr->sin_port;

  /* generate initial sequence number */
  srand((unsigned int)(time(NULL)));
  uint32_t initSeq = rand();

  /* set up first SYN segment */
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header.sequence_no = initSeq;
  frag->header.ack_no = 0;
  frag->header.flags = SOCK352_SYN;

  /* send SYN packet */
  sendto(fd, frag, sizeof(frag), 0, (struct sockaddr *)addr, len);

  /* change connection state */
  conn->state = SYN_SENT;


  /* receive ACK segment */
  recvfrom(fd, frag, sizeof(frag), 0, (struct sockaddr *)addr, &len);

  /* test the acknowledgement number */
  if (frag->header.ack_no != initSeq + 1) 
    return SOCK352_FAILURE;

  /* set up SYNACK segment */
  uint32_t ack = frag->header.sequence_no + 1;
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header.sequence_no = initSeq+1;
  frag->header.ack_no = ack;
  frag->header.flags = SOCK352_ACK;
  
  /* change connection state */
  conn->state = ESTABLISHED;
  return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n)
{
  return listen(fd, n);
}
int sock352_accept(int fd, sockaddr_sock352_t *addr, int *len)
{
	/* wait for a connection packet recvfrom() */
	#define BUFSIZE 2048
	unsigned char buf[BUFSIZE];     		/* receive buffer */
	int byte_count;                    	/* # bytes received */
	byte_count = recvfrom(fd, buf, BUFSIZE, 0, &addr, &len); 

	/* set up sequence and acknowledgement numbers */
  srand((unsigned int)(time(NULL)));
  uint32_t initSeq = rand(); /* generate sequence number */

	/* return a SYS/ACK flagged packet */

	
	/* create empty lists of fragments (receive and send) */

	/* return from accept() call */
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
