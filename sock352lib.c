/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
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

int sock352_init2(int remote_port, int local_port)
{
	return SOCK352_SUCCESS;
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
  
  /* set up connection */
  conn->dest_addr = addr->sin_addr;
  conn->dest_port = addr->sin_port;
  conn->base = 0;
  conn->nextseqnum = 0;
  conn->window_size = WINDOW_SIZE;
  conn->timeout = 0.2 * (uint64_t)(1000000);
  
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
  if (frag->header->ack_no != initSeq + 1 || frag->header->flags != (SOCK352_ACK | SOCK352_SYN))
    return SOCK352_FAILURE;
  
  /* set up the third segment */
  uint64_t ack = frag->header->sequence_no + 1;
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header->sequence_no = initSeq;
  frag->header->ack_no = ack;
  frag->header->flags = 0;
  
  /* send the third segment */
  sendto(conn->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, len);
  
  /* change connection state */
  conn->state = ESTABLISHED;
  
  /* create lists */
  conn->frag_list = NULL;
  conn->wait_to_be_sent = NULL;
  
  /* start timer */
  return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n)
{
  /* find the connection in hash table */
  sock352_connection_t * conn = __sock352_find_active_connection(global_p, fd);
  
  /* change connection state */
  conn->state = LISTEN;
  
  return listen(fd, n);
}

int sock352_accept(int fd, sockaddr_sock352_t *addr, int *len)
{
  sock352_connection_t *conn = __sock352_find_active_connection(global_p, fd);
  
  /* set up the destination address and port in this connection */
  conn->dest_addr = addr->sin_addr;
  conn->dest_port = addr->sin_port;
  /* set expected sequence number to 0 */
  conn->expectedseqnum = 0;
  
  /* receive SYN packet */
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
  
  /* change connection state */
  if (recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)addr, (socklen_t *)len) < 0) {
    return SOCK352_FAILURE;
  } else {
    conn->state = SYN_RCVD;
  }
  
  /* set up sequence numbers */
  srand((unsigned int)(time(NULL)));
  uint32_t seq = rand();
  
  /* set up acknowledgement number (ACK = SEQ + 1) */
  uint64_t ack = frag->header->sequence_no + 1;
  
  /* set up SYN/ACK segment */
  frag->header->sequence_no = seq;
  frag->header->ack_no = ack;
  frag->header->flags = SOCK352_ACK | SOCK352_SYN;
  
  /* return a SYSACK flagged packet */
  sendto(conn->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, *len);
  
  /* change connection state */
  if (recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)addr, (socklen_t *)len) < 0) {
    return SOCK352_FAILURE;
  } else {
    conn->state = ESTABLISHED;
  }
  
  
  /* create empty lists of fragments to receive */
  conn->frag_list = NULL;			/* important to initialize header to NULL! */
  
  /* return from accept() call */
  return fd;
}

int sock352_close(int fd)
{
  return 1;
}

int sock352_read(int fd, void *buf, int count)
{
  /* Block waiting for a UDP packet */
  /* Receive packet function */
  sock352_connection_t * conn = __sock352_find_active_connection(global_p, fd);
  
  if (conn->state != ESTABLISHED) {
    return SOCK352_FAILURE;
  }
  
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
  
  struct sockaddr_in addr;
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = conn->dest_addr;
  addr.sin_port = conn->dest_port;
  socklen_t len= (socklen_t) sizeof(addr);
  if (recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, &len) < 0) {
    return SOCK352_FAILURE;
  }
  
  /* Lock the connection */
  pthread_mutex_lock (&conn->lock);
  
  
  /* if packet is not corrupt, and sequence number is correct */
  if ((__sock352_verify_checksum(frag)) && (conn->expectedseqnum == frag->header->sequence_no)) {
    conn->expectedseqnum++;
    
  }
  __sock352_send_ack(conn);
  
  
  DL_APPEND(conn->frag_list, frag);
  
  
  /* unlock */
  pthread_mutex_unlock (&conn->lock);
  pthread_exit(NULL);
  /* Return from the read call. */
  return SOCK352_SUCCESS;
}

int sock352_write(int fd, void *buf, int count)
{
  /* find the connection in hash table */
  sock352_connection_t * conn = __sock352_find_active_connection(global_p, fd);
  
  /* use mutex to lock the connection */
  pthread_mutex_lock (&conn->lock);
  
  /* connection should be built before transmit data */
  if (conn->state != ESTABLISHED) {
    printf("connection is not built before transmit data");
    return SOCK352_FAILURE;
  }
  
  /* create a new fragment */
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  /* create a packet header */
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
  
  /* include data */
  frag->data = buf;
  /* set up header */
  frag->header->flags = 0;
  frag->header->payload_len = count;
  /* create checksum */
  __sock352_compute_checksum(frag);

  /* append it to waiting to be sent list */
  DL_APPEND(conn->wait_to_be_sent, frag);
  
  /* if the window is not full */
  while (conn->nextseqnum < conn->base+conn->window_size) {
    sock352_fragment_t *elt, *del = conn->wait_to_be_sent;
    int count;
    
    /* delete the first fragment in wait to be sent list */
    DL_DELETE(conn->wait_to_be_sent, del);
    del->header->sequence_no = conn->nextseqnum;

    del->timestamp = __sock352_get_timestamp();
    
    /* apeend to send list */
    DL_APPEND(conn->frag_list, del);
    
    /* send packet (header + data) */
    __sock352_send_fragment(conn, frag);
    
    if (conn->base == conn->nextseqnum) {
      __sock352_timeout_init(conn);
    }
    
    DL_COUNT(conn->wait_to_be_sent, elt, count);
    if (count == 0) break;
   
     conn->nextseqnum++;
  }

  
  /* unlock the connection and exit */
  pthread_mutex_unlock (&conn->lock);
  pthread_exit(NULL);
  
  return frag->header->payload_len;
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
  pthread_t tid;
  pthread_create(&tid, NULL, timer, ptr);
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
  struct sockaddr_in addr;
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = connection->dest_addr;
  addr.sin_port = connection->dest_port;
  
  /* resend every fragment in the send list, and reset their timestamp */
  sock352_fragment_t *elt;
  DL_FOREACH(connection->frag_list, elt) {
    sendto(connection->sock352_fd, (char *)elt, sizeof(elt), 0, (struct sockaddr *)&addr, sizeof(addr));
    elt->timestamp = __sock352_get_timestamp();
  }
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

uint64_t __sock352_lapsed_usec(struct timeval * start, struct timeval *end)
{
  return 0;
}

void __sock352_compute_checksum(sock352_fragment_t *fragment)
{
  MD5_CTX md5_context;
  MD5_Init(&md5_context);
  MD5_Update(&md5_context, fragment->data, fragment->header->payload_len);
  MD5_Final(fragment->header->checksum, &md5_context);
}

int __sock352_verify_checksum(sock352_fragment_t *fragment)
{
  uint16_t verify;
  MD5_CTX md5_context;
  MD5_Init(&md5_context);
  MD5_Update(&md5_context, fragment->data, fragment->header->payload_len);
  MD5_Final(verify, &md5_context);
  return (verify == fragment->header->checksum);
}

uint64_t __sock352_get_timestamp()
{
  struct timeval time;
  gettimeofday(&time, (struct timezone *) NULL);
  return ((uint64_t) time.tv_sec  * (uint64_t)(1000000) + (uint64_t )time.tv_usec);
}

void *receiver(void* arg)
{
  sock352_connection_t *conn = (sock352_connection_t*) arg;
  
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
  
  struct sockaddr_in addr;
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = conn->dest_addr;
  addr.sin_port = conn->dest_port;
  socklen_t len= (socklen_t) sizeof(addr);
  if (recvfrom(conn->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, &len) < 0) {
    ;
  }
  
  /* ack_no == the first sequence_no */
  if (frag->header->ack_no == conn->frag_list->header->sequence_no) {
    sock352_fragment_t *del = conn->frag_list;
    DL_DELETE(conn->frag_list, del);
    free(del);
    conn->base++;
  } else {
    
  }
  
  return NULL;
}

void * timer(void * arg)
{
  sock352_connection_t *conn = (sock352_connection_t*) arg;
  
  
  while (1) {
    pthread_mutex_lock(&conn->lock);
    uint64_t current_time = __sock352_get_timestamp();
    
    /* when timeout event occurs */
    if (current_time - conn->frag_list->timestamp > conn->timeout) {
      __sock352_send_expired_fragments(conn);
    }
    
    /* when send buffer is empty, terminate this thread */
    if (conn->base == conn->nextseqnum) {
      break;
    }
    pthread_mutex_unlock(&conn->lock);
  }

  return NULL;
}




