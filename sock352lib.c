/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include <errno.h>
#include "sock352lib.h"

int sock352_init(int udp_port)
{
  if (udp_port != 0) {
    return SOCK352_FAILURE;
  }
  else {
    /* socket port numbers to use */
    sock352_fd_base = 0;
    all_connections = NULL;
    sock352_remote_port = SOCK352_DEFAULT_UDP_PORT;
    sock352_local_port = SOCK352_DEFAULT_UDP_PORT;
    return SOCK352_SUCCESS;
  }
}

int sock352_init2(int remote_port, int local_port)
{
  /* socket port numbers to use */
  sock352_fd_base = 0;
  all_connections = NULL;
  sock352_remote_port = remote_port;
  sock352_local_port = local_port;
  return SOCK352_SUCCESS;
}

int sock352_init3(int remote_port,int local_port, char *envp[] ) {
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
  master_fd = socket(AF_INET, SOCK_DGRAM, 0);
  sock352_connection_t *conn = __sock352_create_connection();
  return conn->sock352_fd;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  return SOCK352_SUCCESS;
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  /* bind */
  struct sockaddr_in local_addr;
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  local_addr.sin_port = htons(sock352_local_port);
  int local_len = sizeof(local_addr);
  bind(master_fd, (struct sockaddr *)&local_addr, local_len);
  
  struct sockaddr_in remote_addr;
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = addr->sin_addr.s_addr;
  remote_addr.sin_port = htons(sock352_remote_port);
  int remote_len = sizeof(remote_addr);
  
  /* set up connection */
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  memcpy(&conn->dest, &remote_addr, sizeof(remote_addr));
  
  /*
  struct timeval timeout={0,2};
  if (setsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    perror("fail to setsockopt");
    exit(-1);
  }*/
  
 /* set up first SYN segment */
  sock352_fragment_t *SYN_frag = __sock352_create_fragment();
  srand((unsigned int)(time(NULL)));
  SYN_frag->header.sequence_no = rand();
  SYN_frag->header.ack_no = 0;
  SYN_frag->header.flags = SOCK352_SYN;
  
  /* send SYN packet */
  
  if (sendto(master_fd, (char *)SYN_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
    fprintf(stderr, "errno %d: %s\n",errno, strerror(errno));
    printf("Eorror in sending SYN packet\n");
    return SOCK352_FAILURE;
  }
  
  /* receive SYNACK segment */
  sock352_fragment_t *SYNACK_frag = __sock352_create_fragment();
  while (1) {
    if (recvfrom(master_fd, (char *)SYNACK_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, &remote_len) < 0) {
      /* timeout occurs, resend */
      if (errno == EAGAIN) {
        if (sendto(master_fd, (char *)SYN_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
          printf("Eorror in sending SYN packet\n");
          return SOCK352_FAILURE;
        }
      }
    }
    else {
      /* acknowledgement number is wrong, resend */
      if (SYNACK_frag->header.ack_no != SYN_frag->header.sequence_no + 1 || SYNACK_frag->header.flags != (SOCK352_ACK | SOCK352_SYN)) {
        printf("Eorror in received SYNACK packet");
        if (sendto(master_fd, (char *)SYN_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
          printf("Eorror in sending SYN packet");
          return SOCK352_FAILURE;
        }
      }
      else
        break;
    }
  }
  
  /* set up the third segment */
  sock352_fragment_t *ACK_frag = __sock352_create_fragment();
  ACK_frag->header.sequence_no = SYN_frag->header.sequence_no;
  ACK_frag->header.ack_no = SYNACK_frag->header.sequence_no + 1;
  ACK_frag->header.flags = SOCK352_ACK;
  
  /* send the third segment */
  if (sendto(master_fd, (char *)ACK_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
    printf("Eorror in sending ACK packet");
    return SOCK352_FAILURE;
  }
  
  conn->base = 1;
  conn->nextseqnum = 1;
  conn->expectedseqnum = 1;
  conn->window_size = WINDOW_SIZE;
  conn->timeout = 0.2 * (uint64_t)(1000000);
  /* create lists */
  conn->send_list = NULL;
  conn->recv_list = NULL;
 
  __sock352_destroy_fragment(SYN_frag);
  __sock352_destroy_fragment(SYNACK_frag);
  __sock352_destroy_fragment(ACK_frag);
  
  __sock352_receiver_init(&fd);
 
  return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int backlog)
{  
  return SOCK352_SUCCESS;
}

int sock352_accept(int fd, sockaddr_sock352_t *addr, int *len)
{
  /* bind */
  struct sockaddr_in local_addr;
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  local_addr.sin_port = htons(sock352_local_port);
  int local_len = sizeof(local_addr);
  bind(master_fd, (struct sockaddr *)&local_addr, local_len);
  
  struct sockaddr_in remote_addr;
  int remote_len = sizeof(remote_addr);
  
  /* receive SYN packet */
  sock352_fragment_t *SYN_frag = __sock352_create_fragment();
  while (1) {
    long size;
    if ((size = recvfrom(master_fd, SYN_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, &remote_len)) < 0) {
      printf("Eorror in sending SYNACK packet");
      return SOCK352_FAILURE;
    }
    else {
      if (SYN_frag->header.flags == SOCK352_SYN) {
        break;
      }
    }
    bzero(SYN_frag, sizeof(sock352_fragment_t));
  }
  
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  conn->passive = 1;
  memcpy(&conn->dest, &remote_addr, sizeof(remote_addr));;
  
  sock352_connection_t *new_conn = __sock352_create_connection();
  memcpy(&new_conn->dest, &remote_addr, sizeof(remote_addr));
  
  /* set up SYN/ACK segment */
  sock352_fragment_t *SYNACK_frag = __sock352_create_fragment();
  srand((unsigned int)(time(NULL)));
  SYNACK_frag->header.sequence_no = rand();
  SYNACK_frag->header.ack_no = SYN_frag->header.sequence_no + 1;
  SYNACK_frag->header.flags = SOCK352_ACK | SOCK352_SYN;
  
  /*
  struct timeval timeout={0,2};
  if (setsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    perror("fail to setsockopt");
    exit(-1);
  }
   */
  
  /* return a SYSACK flagged packet */
  if (sendto(master_fd, (char *)SYNACK_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
    printf("Eorror in sending SYNACK packet");
    return SOCK352_FAILURE;
  }
  
  sock352_fragment_t *ACK_frag = __sock352_create_fragment();
  if (recvfrom(master_fd, (char *)ACK_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, &remote_len) < 0) {
        return SOCK352_FAILURE;
  }
  
  __sock352_destroy_fragment(SYN_frag);
  __sock352_destroy_fragment(SYNACK_frag);
  __sock352_destroy_fragment(ACK_frag);
  
  new_conn->base = 1;
  new_conn->nextseqnum = 1;
  new_conn->expectedseqnum = 1;
  new_conn->window_size = WINDOW_SIZE;
  new_conn->timeout = 0.2 * (uint64_t)(1000000);
  /* create empty lists of fragments to receive */
  new_conn->send_list = NULL;			/* important to initialize header to NULL! */
  new_conn->recv_list = NULL;
  
  __sock352_receiver_init(&new_conn->sock352_fd);
  /* return from accept() call */
  return new_conn->sock352_fd;
}

int sock352_close(int fd)
{
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  pthread_mutex_lock(&conn->lock);
  
  if (conn->passive == 0) {
    sock352_fragment_t *FIN_frag = __sock352_create_fragment();
    FIN_frag->header.flags = SOCK352_FIN;
    
    if (sendto(master_fd, (char *)FIN_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&conn->dest, sizeof(conn->dest)) < 0) {
      printf("Eorror in sending FIN packet");
      return SOCK352_FAILURE;
    }
    __sock352_destroy_fragment(FIN_frag);
    
    printf("FIN sent\n");
    
    while (1) {
    if (conn->close == 1) {
      sock352_fragment_t *elt;
      int recv_count, send_count;
      DL_COUNT(conn->recv_list, elt, recv_count);
      DL_COUNT(conn->send_list, elt, send_count);
      if (!recv_count && !send_count) {
        break;
      }
    }
    else {
      pthread_mutex_unlock(&conn->lock);
      sleep(1);
      pthread_mutex_lock(&conn->lock);
    }
  }
  }
  pthread_mutex_unlock(&conn->lock);
  sleep(5);
  __sock352_destroy_connection(conn);
  if (fd == 0) {
    close(master_fd);
    all_connections = NULL;
  }
  return SOCK352_SUCCESS;
}

int sock352_read(int fd, void *buf, int count)
{
  int ret = 0;
  sock352_connection_t * conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  pthread_mutex_lock (&conn->lock);
  
  sock352_fragment_t *elt;
  int frag_count;
  while (1) {
    DL_COUNT(conn->recv_list, elt, frag_count);
    if (frag_count != 0) {
      /*copy data to buffer*/
      sock352_fragment_t *frag = conn->recv_list;
      ret = frag->header.payload_len;
      memcpy(buf, frag->data, ret);
      DL_DELETE(conn->recv_list, frag);
      __sock352_destroy_fragment(frag);
      break;
    }
    else {
      pthread_mutex_unlock(&conn->lock);
      sleep(1);
      pthread_mutex_lock(&conn->lock);
    }
  }
  pthread_mutex_unlock (&conn->lock);

  /* Return from the read call. */
  return ret;
}

int sock352_write(int fd, void *buf, int count)
{
  /* find the connection in hash table */
  int ret;
  sock352_connection_t * conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  /* use mutex to lock the connection */
  pthread_mutex_lock(&conn->lock);
  
  /* if the window is full, block for signal */
  if (conn->nextseqnum == conn->base+conn->window_size) {
    pthread_cond_wait(&conn->base_change, &conn->lock);
  }
  sock352_fragment_t *frag = __sock352_create_fragment();
  memcpy(frag->data, buf, count);
  frag->header.flags = 0;
  frag->header.payload_len = count;
  frag->header.checksum = __sock352_compute_checksum(frag);
  frag->header.sequence_no = conn->nextseqnum;
  frag->timestamp = __sock352_get_timestamp();
  /* apeend to send list */
  DL_APPEND(conn->send_list, frag);
  
  if (sendto(master_fd, (char *)frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&conn->dest, sizeof(conn->dest)) < 0) {
    printf("Eorror in sending packet");
    return SOCK352_FAILURE;
  }
  
  printf("sent packet\n");
  
  if (conn->base == conn->nextseqnum) {
    __sock352_timer_init(&fd);
  }
  conn->nextseqnum++;
  pthread_mutex_unlock (&conn->lock);
  ret = count;
  return ret;
}


/* receiver thread for client and server*/
void *receiver(void* arg)
{
  int fd = *((int*)arg);
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  size_t bytes_count;
  
  struct sockaddr_in remote_addr;
  socklen_t remote_len= sizeof(remote_addr);
  while (1) {
    sock352_fragment_t *frag = __sock352_create_fragment();
    if ((bytes_count = recvfrom(master_fd, (char *)frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, &remote_len)) == -1) {
      perror("Eorror in receiving packet\n");
    }
    /*else if (bytes_count == 0) {
      pthread_exit(NULL);
    }*/
    else {
      pthread_mutex_lock (&conn->lock);
      if (frag->header.flags == 0 && __sock352_verify_checksum(frag) && frag->header.sequence_no == conn->expectedseqnum) {
        printf("received packet\n");
        DL_APPEND(conn->recv_list, frag);
        __sock352_send_ack(conn);
        conn->expectedseqnum++;
      }
      else if (frag->header.flags == SOCK352_ACK) {
        printf("received ack\n");
        sock352_fragment_t *del = conn->send_list;
        DL_DELETE(conn->send_list, del);
        free(del);
        conn->base++;
        pthread_cond_signal(&conn->base_change);
        if (conn->base != conn->nextseqnum)
          __sock352_timer_init(arg);
        free(frag);
      }
      else if (frag->header.flags == SOCK352_FIN) {
        conn->close = 1;
        free(frag);
      }
      else {
        free(frag);
      }
      pthread_mutex_unlock (&conn->lock);
    }
  }
}

void * timer(void * arg)
{
  int fd = *((int*)arg);
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  while (1) {
    pthread_mutex_lock(&conn->lock);
    
    if (conn->base == conn->nextseqnum) {
      pthread_mutex_unlock(&conn->lock);
      pthread_exit(NULL);
    }
    
    /* when timeout event occurs */
    uint64_t current_time = __sock352_get_timestamp();
    if (current_time - conn->send_list->timestamp > conn->timeout) {
      __sock352_send_expired_fragments(conn);
    }
    pthread_mutex_unlock(&conn->lock);
//    pthread_testcancel();
  }
}


/* Internal Functions */
void __sock352_receiver_init(void *arg)
{
  pthread_create(&receiver_thread, NULL, receiver, arg);
}

void __sock352_timer_init(void *arg)
{
  pthread_create(&timer_thead, NULL, timer, arg);
}

sock352_connection_t * __sock352_create_connection()
{
  sock352_connection_t *conn = malloc(sizeof(sock352_connection_t));
  bzero(conn, sizeof(sock352_connection_t));
  conn->sock352_fd = sock352_fd_base++;
  conn->passive = 0;
  conn->close = 0;
  pthread_mutex_init(&conn->lock, NULL);
  pthread_cond_init(&conn->base_change, NULL);
  HASH_ADD_INT(all_connections, sock352_fd, conn);
  return conn;
}

void __sock352_destroy_connection(sock352_connection_t * conn)
{
  HASH_DEL(all_connections, conn);
  free(conn);
}

sock352_fragment_t * __sock352_create_fragment()
{
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  bzero(frag, sizeof(sock352_fragment_t));
  return frag;
}

void __sock352_destroy_fragment(sock352_fragment_t *frag)
{
  if (frag != NULL) {
    free(frag);
  }
}

int __sock352_send_ack(sock352_connection_t *conn)
{
  sock352_fragment_t *frag = __sock352_create_fragment();
  frag->header.flags = SOCK352_ACK;
  frag->header.ack_no = conn->expectedseqnum;
  
  if (sendto(master_fd, (char *)frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&conn->dest, sizeof(conn->dest)) < 0) {
    printf("Eorror in sending ACK");
  }
  printf("sent ack\n");
  free(frag);
  return 0;
}

int __sock352_send_expired_fragments(sock352_connection_t *conn)
{
  /* resend every fragment in the send list, and reset their timestamp */
  sock352_fragment_t *elt;
  DL_FOREACH(conn->send_list, elt) {
    if (sendto(master_fd, (char *)elt, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&conn->dest, sizeof(conn->dest)) < 0) {
      printf("Eorror in sending packet");
      return SOCK352_FAILURE;
    }
    elt->timestamp = __sock352_get_timestamp();
  }
  return 0;
}

uint64_t __sock352_lapsed_usec(struct timeval * start, struct timeval *end)
{
  return 0;
}

uint16_t __sock352_compute_checksum(sock352_fragment_t *fragment) {
  int len = fragment->header.payload_len;
  
  uint32_t sum = 0;  /* assume 32 bit long, 16 bit short */
  uint16_t *buf = (uint16_t *)fragment->data;
  while(len > 1){
    sum += *buf++;
    if(sum & 0x80000000)   /* if high order bit set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }
  
  if(len)
    sum += (uint16_t) *(uint32_t *)buf;
  
  while(sum>>16) /* take care of left over byte */
    sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
}

int __sock352_verify_checksum(sock352_fragment_t *fragment)
{
  uint16_t verify = __sock352_compute_checksum(fragment);
  return (verify == fragment->header.checksum);
}

uint64_t __sock352_get_timestamp()
{
  struct timeval time;
  gettimeofday(&time, (struct timezone *) NULL);
  return ((uint64_t) time.tv_sec  * (uint64_t)(1000000) + (uint64_t )time.tv_usec);
}





