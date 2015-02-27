/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <md5.h>
#include "sock352lib.h"

int sock352_init(int udp_port)
{
  if (udp_port != 0) {
    return SOCK352_FAILURE;
  } 
  else {
    /* timeout thread */

    /* global structure for all connections */ 

    global_p = malloc(sizeof(sock352_global_t));
    global_p->active_connections = (sock352_connection_t *) NULL;
    global_p->sock352_base_fd = 0;

    /* socket port numbers to use */
    global_p->sock352_recv_port = SOCK352_DEFAULT_UDP_PORT;

    return SOCK352_SUCCESS;
  }
}

int sock352_socket(int domain, int type, int protocol)
{
	/* ensure that the domain and type are correct */
  if (domain != AF_CS352) {
    return SOCK352_FAILURE;
  }

  if (type != SOCK_STREAM) {
    return SOCK352_FAILURE;
  }
  
  /*create connection and initialize state and file descriptor */
  int fd = socket(domain, type, protocol);
  sock352_connection_t * conn = malloc(sizeof(sock352_connection_t));
  memset(conn, 0, sizeof(sock352_connection_t));
  conn->state = CLOSED;
  conn->sock352_fd = fd;

  /* add connection to the list of active connections */
  HASH_ADD_INT(global_p->active_connections, sock352_fd, conn);
  return fd;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  /* find the connection in hash table */
  sock352_connection_t * conn; 
  conn = __sock352_find_active_connection(global_p, fd);
  
  /* set up the source address and port in this connection */
  conn->src_addr = addr->sin_addr;
  conn->src_port = addr->sin_port;
  
  return bind(fd, (struct sockaddr *)&addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  /* find the connection in hash table */
  sock352_connection_t * conn = __sock352_find_active_connection(global_p, fd);

  /* set up the destination address and port in this connection */
  conn->dest_addr = addr->sin_addr;
  conn->dest_port = addr->sin_port;

  /* generate initial sequence number */
  srand((unsigned int)(time(NULL)));
  uint32_t initSeq = rand();

  /* set up first SYN segment */
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
  frag->header->sequence_no = initSeq;
  frag->header->ack_no = 0;
  frag->header->flags = SOCK352_SYN;

  /* send SYN packet */
  sendto(conn->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, len);

  /* change connection state */
  conn->state = SYN_SENT;

  /* receive ACK segment */
  recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)addr, &len);

  /* test the acknowledgement number */
  if (frag->header->ack_no != initSeq + 1 || frag->header->flags != SOCK352_ACK)
    return SOCK352_FAILURE;

  /* set up SYN/ACK segment */
  uint64_t ack = frag->header->sequence_no + 1;
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header->sequence_no = initSeq;
  frag->header->ack_no = ack;
  frag->header->flags = SOCK352_ACK;
  
  /* send SYN/ACK segment */
  sendto(conn->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, len);
  
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
  sock352_connection_t *conn = __sock352_find_active_connection(global_p, fd);

  /* set up the destination address and port in this connection */
  conn->dest_addr = addr->sin_addr;
  conn->dest_port = addr->sin_port;

  /* wait for a connection packet using recvfrom() */
	sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
	recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)addr, (socklen_t *)len);

	/* set up sequence numbers */
  srand((unsigned int)(time(NULL)));
  uint32_t seq = rand();

  /* set up acknowledgement number (ACK = SEQ + 1) */
	uint64_t ack = frag->header->sequence_no + 1;

	/* set up SYN/ACK segment */
  frag->header->sequence_no = seq;
  frag->header->ack_no = ack;
  frag->header->flags = SOCK352_ACK;

	/* return a SYS/ACK flagged packet */
  __sock352_send_fragment(conn, frag);
  
	/* create empty lists of fragments (receive and send) */
  sock352_fragment_t *receive_list = NULL;			/* important to initialize header to NULL! */
  sock352_fragment_t *send_list = NULL;

	/* return from accept() call */
  return SOCK352_SUCCESS;
}

int sock352_close(int fd)
{
  return close(fd);
}

int sock352_read(int fd, void *buf, int count)
{
  
  return SOCK352_SUCCESS;

  /* Block waiting for a UDP packet */
	/* Receive packet function */
	/* Lock the connection */
	/* Update transmit list with new ack# */
	/* Find the place on the recv fragment list */
	/* Insert the fragment */
	/* Find the lowest # fragment */ 
	/* send an ACK with the highest sequence */
	/* Copy the data from the read pointer */
	/* unlock */
	/* Return from the read call. */
}

int sock352_write(int fd, void *buf, int count)
{
  /* find the connection in hash table */
  sock352_connection_t * conn = __sock352_find_active_connection(global_p, fd);

  /* if the window is not full */
  if (conn->nextseqnum < conn->base+conn->window_size) {
  	/* use mutex to lock the connection */
  	pthread_mutex_t mutex_connection;	
  	pthread_mutex_lock (&mutex_connection);

    /* create a new fragment */
    sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
    memset(frag, 0, sizeof(sock352_fragment_t));
    
    /* create a packet header */
    frag->header = malloc(sizeof(sock352_pkt_hdr_t));
    memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
    frag->header->sequence_no = conn->nextseqnum;

		/* include data */
		    
    /* create checksum */  
    MD5_CTX md5_context;
    MD5Init(&md5_context);
    MD5Update(&md5_context, frag->data, frag->size);
    MD5Final(frag->header->checksum, &md5_context);

    /* send packet (header + data) */
    struct sockaddr_in remote_addr; 
    memset((char *)&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = conn->dest_addr;
    remote_addr.sin_port = conn->dest_port;
    sendto(fd, frag, sizeof(frag), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr));

    __sock352_send_fragment(conn, frag);


    /* record the time sent */
    if (conn->base == conn->nextseqnum) {
      //start-timer
    }
    conn->nextseqnum++;

    /* unlock the connection and exit */
    pthread_mutex_unlock (&mutex_connection);
    pthread_exit(NULL);
  }
  else
    //refuse data to upper level;

  /*
  	-lock the connection
  	-create a new fragment
  	-create a new packet header for this fragment
  	-add it to the transmit list
  	-send the header + data
  	-record the time sent
  	-unlock the connection
  */
  return SOCK352_SUCCESS;
}



/* Internal Functions */
int __sock352_init(int remote_port, int local_port)
{
  return 0;
}

void __sock352_reader_init(void *ptr)
{

}
void __sock352_timeout_init(void *ptr)
{

}
int __sock352_input_packet(sock352_global_t *global_p)
{
  return 0;
}
int __sock352_send_fragment(sock352_connection_t *connection,sock352_fragment_t *fragment)
{
  struct sockaddr_in addr;
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = connection->dest_addr;
  addr.sin_port = connection->dest_port;
  
  sendto(connection->sock352_fd, (char *)fragment, sizeof(fragment), 0, (struct sockaddr *)&addr, sizeof(addr));
  
  return 0;
}
int __sock352_send_ack(sock352_connection_t *connection)
{
  return 0;
}
int __sock352_send_expired_fragments(sock352_connection_t *connection)
{
  return 0;
}
sock352_connection_t * __sock352_find_active_connection(sock352_global_t *global_p, int fd)
{
  sock352_connection_t *conn;
  HASH_FIND_INT(global_p->active_connections, &fd, conn);
  return conn;
}
sock352_connection_t * __sock352_find_accept_connection(sock352_global_t *global_p, sock352_pkt_hdr_t *pkt_hdr)
{
  return 0;
}
int __sock352_connection_return(sock352_global_t *global_p, sock352_pkt_hdr_t * pkt_hdr, sock352_connection_t *connection)
{
  return 0;
}
int __sock352_accept_return(sock352_pkt_hdr_t *pkt_rx_hdr,sock352_connection_t *connection)
{
  return 0;
}
uint64_t __sock352_lapsed_usec(struct timeval * start, struct timeval *end)
{
  return 0;
}
int __sock352_add_tx_fragment(sock352_connection_t *connection, sock352_fragment_t *fragment)
{
  return 0;
}
int __sock352_remove_tx_fragment(sock352_connection_t * active_connection,sock352_fragment_t *fragment)
{
  return 0;
}
int __sock352_enqueue_data_packet(sock352_connection_t *connection,uint8_t *data, int header_size, int data_size)
{
  return 0;
}
int __sock352_add_rx_fragment(sock352_connection_t *connection, sock352_fragment_t *fragment)
{
  return 0;
}


