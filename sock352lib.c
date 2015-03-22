/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include "sock352lib.h"

int sock352_init(int udp_port)
{
  if (udp_port != 0) {
    return SOCK352_FAILURE;
  }
  else {
    
    /* global structure for all connections */
    global_p = malloc(sizeof(sock352_global_t));
    global_p->active_connections = (sock352_connection_t *) NULL;
    
    /* socket port numbers to use */
    global_p->sock352_remote_port = SOCK352_DEFAULT_UDP_PORT;
    global_p->sock352_local_port = SOCK352_DEFAULT_UDP_PORT;
    return SOCK352_SUCCESS;
  }
}

int sock352_init2(int remote_port, int local_port)
{
  /* global structure for all connections */
  global_p = malloc(sizeof(sock352_global_t));
  global_p->active_connections = (sock352_connection_t *) NULL;
  
  /* socket port numbers to use */
  global_p->sock352_remote_port = remote_port;
  global_p->sock352_local_port = local_port;
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
  
  global_p->domain = domain;
  global_p->protocol = protocol;
  
  /*create connection and initialize state and file descriptor */
  int fd = socket(domain, SOCK_DGRAM, protocol);/////////////////////////////////////////////
  global_p->current_connection = malloc(sizeof(sock352_connection_t));
  memset(global_p->current_connection, 0, sizeof(sock352_connection_t));
  global_p->current_connection->state = CLOSED;
  global_p->current_connection->sock352_fd = fd;

  return fd;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  /* set up the source address and port in this connection */
  global_p->current_connection->src_addr = addr->sin_addr;
  global_p->current_connection->src_port = addr->sin_port;
  
  return bind(fd, (struct sockaddr *)&addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  
  ///////////////////////////////////////////////////////////////////////////////////////////
  //bind() ???
  
  /* set up connection */
  global_p->current_connection->dest_addr = addr->sin_addr;
  global_p->current_connection->dest_port = addr->sin_port;
  global_p->current_connection->base = 0;
  global_p->current_connection->nextseqnum = 0;
  global_p->current_connection->window_size = WINDOW_SIZE;
  global_p->current_connection->timeout = 0.2 * (uint64_t)(1000000);
  
  /* generate initial sequence number */
  srand((unsigned int)(time(NULL)));
  uint32_t initSeq = rand();
  
  /* set up first SYN segment */
  sock352_fragment_t *frag = __sock352_create_fragment();
  frag->header->sequence_no = initSeq;
  frag->header->ack_no = 0;
  frag->header->flags = SOCK352_SYN;
  
  /* send SYN packet */
  if (sendto(global_p->current_connection->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, len) < 0) {
    printf("Eorror in sending SYN packet");
    return SOCK352_FAILURE;
  }
  
  /* change connection state */
  global_p->current_connection->state = SYN_SENT;
  
  /* receive ACK segment */
  memset(frag, 0, sizeof(sock352_fragment_t));
  if (recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)addr, &len) < 0) {
    printf("Error in receiving the SYNACK packet");
    return SOCK352_FAILURE;
  }
  
  /* test the acknowledgement number */
  if (frag->header->ack_no != initSeq + 1 || frag->header->flags != (SOCK352_ACK | SOCK352_SYN)) {
    printf("Eorror in received SYNACK packet");
    return SOCK352_FAILURE;
  }
  
  /* set up the third segment */
  uint64_t ack = frag->header->sequence_no + 1;
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header->sequence_no = initSeq;
  frag->header->ack_no = ack;
  frag->header->flags = SOCK352_ACK;
  
  /* send the third segment */
  if (sendto(global_p->current_connection->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, len) < 0) {
    printf("Eorror in sending ACK packet");
    return SOCK352_FAILURE;
  }
  
  /* change connection state */
  global_p->current_connection->state = ESTABLISHED;
  
  /* create lists */
  global_p->current_connection->send_list = NULL;
  global_p->current_connection->wait_to_be_sent = NULL;
  
  __sock352_destroy_fragment(frag);
  return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n)//////////////////////////////////////////////////////////////////
{
  /* receive SYN packet */
  sock352_fragment_t *frag = __sock352_create_fragment();
  struct sockaddr_storage addr;
  socklen_t len= sizeof(addr);
  if (recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, &len) < 0) {
    printf("Error in receiving SYN packet");
    return SOCK352_FAILURE;
  }
  
  /* change connection state */
  global_p->current_connection->state = SYN_RCVD;
  
  /* create entry on incomplete connection queue */
  

  /* set up sequence numbers */
  srand((unsigned int)(time(NULL)));
  uint32_t seq = rand();
  
  /* set up acknowledgement number (ACK = SEQ + 1) */
  uint64_t ack = frag->header->sequence_no + 1;
  
  /* set up SYN/ACK segment */
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header->sequence_no = seq;
  frag->header->ack_no = ack;
  frag->header->flags = SOCK352_ACK | SOCK352_SYN;
  
  /* return a SYSACK flagged packet */
  sendto(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, len);
  
  memset(frag, 0, sizeof(sock352_fragment_t));
  if (recvfrom(fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, &len) < 0) {
    printf("Error in receiving the ACK packet");
    return SOCK352_FAILURE;
  }
  
  /* test the acknowledgement number */
  if (frag->header->ack_no != seq + 1 || frag->header->flags != SOCK352_ACK) {
    printf("Eorror in received ACK packet");
    return SOCK352_FAILURE;
  }
  
  /* entry moved from incomplete queue to completed queue */
  
  
  return SOCK352_SUCCESS;
}

int sock352_accept(int fd, sockaddr_sock352_t *addr, int *len)
{
  /* new file descriptor */
  int new_fd = socket(global_p->domain, SOCK_DGRAM, global_p->protocol);
  
  sock352_connection_t *conn = malloc(sizeof(sock352_connection_t));
  memset(global_p->current_connection, 0, sizeof(sock352_connection_t));
  conn->sock352_fd = new_fd;
  conn->expectedseqnum = 0;
  conn->state = ESTABLISHED;
  
  /* create empty lists of fragments to receive */
  conn->send_list = NULL;			/* important to initialize header to NULL! */
  
  HASH_ADD_INT(global_p->active_connections, sock352_fd, conn);
  
  /* return from accept() call */
  return new_fd;
}

int sock352_close(int fd)
{
  sock352_connection_t *conn = __sock352_find_active_connection(global_p, fd);
  free(conn);
  return SOCK352_SUCCESS;
}

int sock352_read(int fd, void *buf, int count)
{
  /* Block waiting for a UDP packet */
  /* Receive packet function */
  sock352_connection_t * conn = __sock352_find_active_connection(global_p, fd);
  
  if (conn->state != ESTABLISHED) {
    return SOCK352_FAILURE;
  }
  
  /* Lock the connection */
  pthread_mutex_lock (&conn->lock);
  
  /* polling reveive buffer */
  
  
  /*copy data to buffer*/
  sock352_fragment_t *del = conn->send_list;
  DL_DELETE(conn->send_list, del);
  memcpy(buf, del->data, del->header->payload_len);
  
  /* unlock */
  pthread_mutex_unlock (&conn->lock);
  
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
    DL_APPEND(conn->send_list, del);
    
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
  
  return frag->header->payload_len;
}


/* Internal Functions */
void __sock352_receiver_init(void *ptr)
{
  pthread_t tid;
  pthread_create(&tid, NULL, receiver, ptr);
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

sock352_fragment_t * __sock352_create_fragment()
{
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  memset(frag, 0, sizeof(sock352_fragment_t));
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  memset(frag->header, 0, sizeof(sock352_pkt_hdr_t));
  return frag;
}

void __sock352_destroy_fragment(sock352_fragment_t *frag)
{
  if (frag != NULL) {
    if (frag->header != NULL) {
      free(frag->header);
    }
    free(frag);
  }
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
  struct sockaddr_in addr;
  sock352_fragment_t *fragment = __sock352_create_fragment();
  fragment->header->flags = SOCK352_ACK;
  fragment->header->ack_no = connection->expectedseqnum;
  
  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = connection->dest_addr;
  addr.sin_port = connection->dest_port;
  sendto(connection->sock352_fd, (char *)fragment, sizeof(fragment), 0, (struct sockaddr *)&addr, sizeof(addr));
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
  DL_FOREACH(connection->send_list, elt) {
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

uint64_t __sock352_lapsed_usec(struct timeval * start, struct timeval *end)
{
  return 0;
}

void __sock352_compute_checksum(sock352_fragment_t *fragment)
{
  MD5_CTX md5_context;
  MD5_Init(&md5_context);
  MD5_Update(&md5_context, fragment->data, fragment->header->payload_len);
  MD5_Final(&fragment->header->checksum, &md5_context);
}

int __sock352_verify_checksum(sock352_fragment_t *fragment)
{
  uint16_t verify;
  MD5_CTX md5_context;
  MD5_Init(&md5_context);
  MD5_Update(&md5_context, fragment->data, fragment->header->payload_len);
  MD5_Final(&verify, &md5_context);
  return (verify == fragment->header->checksum);
}

uint64_t __sock352_get_timestamp()
{
  struct timeval time;
  gettimeofday(&time, (struct timezone *) NULL);
  return ((uint64_t) time.tv_sec  * (uint64_t)(1000000) + (uint64_t )time.tv_usec);
}

/* receiver thread for client and server*/
void *receiver(void* arg)
{
  int fd = *((int*)arg);
  sock352_connection_t *conn = __sock352_find_active_connection(global_p, fd);
  
  struct sockaddr_storage addr;
  socklen_t len= sizeof(addr);
  while (1) {
    sock352_fragment_t *frag = __sock352_create_fragment();
    memset(frag, 0, sizeof(sock352_fragment_t));
    if (recvfrom(conn->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, &len) < 0) {
      pthread_exit(NULL);
    }
    if (frag->header->flags == 0) {
      DL_APPEND(conn->reveive_list, frag);
    }
    else if (frag->header->flags == SOCK352_ACK) {
      /* ack_no == the first sequence_no */
      if (frag->header->ack_no == conn->send_list->header->sequence_no) {
        sock352_fragment_t *del = conn->send_list;
        DL_DELETE(conn->send_list, del);
        free(del);
        conn->base++;
      }
      else
        continue;
    }
    else
      ;
  }
}

void * timer(void * arg)
{
  sock352_connection_t *conn = (sock352_connection_t*) arg;
  
  while (1) {
    pthread_mutex_lock(&conn->lock);
    uint64_t current_time = __sock352_get_timestamp();
    
    /* when timeout event occurs */
    if (current_time - conn->send_list->timestamp > conn->timeout) {
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




