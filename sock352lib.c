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
  
  struct sockaddr_in local_addr;
  struct sockaddr_in remote_addr;
  socklen_t local_len;
  socklen_t remote_len;
  struct timeval old_timeout;
  struct timeval timeout;
  socklen_t optlen;
  sock352_connection_t *conn;
  sock352_fragment_t *SYN_frag;
  sock352_fragment_t *SYNACK_frag;
  sock352_fragment_t *ACK_frag;
  
  /* bind */
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  local_addr.sin_port = htons(sock352_local_port);
  local_len = sizeof(local_addr);
  bind(master_fd, (struct sockaddr *)&local_addr, local_len);
  /* set remote address */
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = addr->sin_addr.s_addr;
  remote_addr.sin_port = htons(sock352_remote_port);
  remote_len = sizeof(remote_addr);
  /* set up timeout */
  optlen = sizeof(old_timeout);
  getsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &old_timeout, &optlen);
  timeout.tv_sec = 0;
  timeout.tv_usec = 2;
  if (setsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    perror("fail to setsockopt");
    exit(-1);
  }
  /* set up first SYN segment */
  SYN_frag = __sock352_create_fragment();
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
  printf("sent SYN\n");
  /* receive SYNACK segment */
  while (1) {
    if (recvfrom(master_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_len) < 0) {
      /* timeout occurs, resend */
      if (errno == EAGAIN) {
        if (sendto(master_fd, (char *)SYN_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
          printf("Eorror in sending SYN packet\n");
          return SOCK352_FAILURE;
        }
      }
    }
    else {
      SYNACK_frag = __sock352_create_fragment();
      __sock352_copy_buffer(SYNACK_frag);
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
  printf("received SYNACK\n");
  /* set up ACK segment */
  ACK_frag = __sock352_create_fragment();
  ACK_frag->header.sequence_no = SYN_frag->header.sequence_no;
  ACK_frag->header.ack_no = SYNACK_frag->header.sequence_no + 1;
  ACK_frag->header.flags = SOCK352_ACK;
  /* send ACK segment */
  if (sendto(master_fd, (char *)ACK_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
    printf("Eorror in sending ACK packet");
    return SOCK352_FAILURE;
  }
  printf("sent ACK\n");
  __sock352_destroy_fragment(SYN_frag);
  __sock352_destroy_fragment(SYNACK_frag);
  __sock352_destroy_fragment(ACK_frag);
  /* set up connection */
  HASH_FIND_INT(all_connections, &fd, conn);
  memcpy(&conn->dest, &remote_addr, sizeof(remote_addr));
  conn->base = 0;
  conn->nextseqnum = 0;
  conn->expectedseqnum = 0;
  conn->window_size = WINDOW_SIZE;
  conn->timeout = 0.2 * (uint64_t)(1000000);
  /* initialize lists */
  conn->send_list = NULL;
  conn->recv_list = NULL;
  /* set timeout to default setting */
  if (setsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &old_timeout, optlen) < 0)
  {
    perror("fail to setsockopt");
    exit(-1);
  }
  __sock352_receiver_init(&fd);

  return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int backlog)
{  
  return SOCK352_SUCCESS;
}

int sock352_accept(int fd, sockaddr_sock352_t *addr, int *len)
{
  struct sockaddr_in local_addr;
  struct sockaddr_in remote_addr;
  socklen_t local_len;
  socklen_t remote_len;
  sock352_connection_t *conn;
  sock352_connection_t *new_conn;
  sock352_fragment_t *SYN_frag;
  sock352_fragment_t *SYNACK_frag;
  sock352_fragment_t *ACK_frag;
  
  /* bind */
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  local_addr.sin_port = htons(sock352_local_port);
  local_len = sizeof(local_addr);
  bind(master_fd, (struct sockaddr *)&local_addr, local_len);
  remote_len = sizeof(remote_addr);
  /* receive SYN packet */
  while (1) {
    long size;
    if ((size = recvfrom(master_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_len)) < 0) {
      printf("Eorror in receiving SYN packet");
      return SOCK352_FAILURE;
    }
    else {
      SYN_frag = __sock352_create_fragment();
      __sock352_copy_buffer(SYN_frag);
      if (SYN_frag->header.flags == SOCK352_SYN) {
        break;
      }
    }
    bzero(SYN_frag, sizeof(sock352_fragment_t));
  }
  printf("received SYN\n");
  /* set up SYN/ACK segment */
  SYNACK_frag = __sock352_create_fragment();
  srand((unsigned int)(time(NULL)));
  SYNACK_frag->header.sequence_no = rand();
  SYNACK_frag->header.ack_no = SYN_frag->header.sequence_no + 1;
  SYNACK_frag->header.flags = SOCK352_ACK | SOCK352_SYN;
  /* return a SYSACK flagged packet */
  if (sendto(master_fd, (char *)SYNACK_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&remote_addr, remote_len) < 0) {
    printf("Eorror in sending SYNACK packet");
    return SOCK352_FAILURE;
  }
  printf("sent SYNACK\n");
  if (recvfrom(master_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_len) < 0) {
    printf("Eorror in receiving ACK packet");
    return SOCK352_FAILURE;
  }
  else {
    ACK_frag = __sock352_create_fragment();
    __sock352_copy_buffer(ACK_frag);
    if (ACK_frag->header.flags != SOCK352_ACK) {
      printf("Eorror in received ACK packet\n");
      return SOCK352_FAILURE;
    }
  }
  printf("received ACK\n");
  __sock352_destroy_fragment(SYN_frag);
  __sock352_destroy_fragment(SYNACK_frag);
  __sock352_destroy_fragment(ACK_frag);
  /* set up connection */
  HASH_FIND_INT(all_connections, &fd, conn);
  conn->passive = 1;
  memcpy(&conn->dest, &remote_addr, sizeof(remote_addr));;
  new_conn = __sock352_create_connection();
  memcpy(&new_conn->dest, &remote_addr, sizeof(remote_addr));
  new_conn->base = 0;
  new_conn->nextseqnum = 0;
  new_conn->expectedseqnum = 0;
  new_conn->window_size = WINDOW_SIZE;
  new_conn->timeout = 0.2 * (uint64_t)(1000000);
  /* initialize lists */
  new_conn->send_list = NULL;			/* important to initialize header to NULL! */
  new_conn->recv_list = NULL;
  __sock352_receiver_init(&new_conn->sock352_fd);
  /* return from accept() call */
  return new_conn->sock352_fd;
}

int sock352_close(int fd)
{
  sock352_connection_t *conn;
  sock352_fragment_t *FIN_frag;
  
  HASH_FIND_INT(all_connections, &fd, conn);
  if (conn->passive == 0) {
    pthread_mutex_lock(&conn->lock);
    FIN_frag = __sock352_create_fragment();
    FIN_frag->header.flags = SOCK352_FIN;
    if (sendto(master_fd, (char *)FIN_frag, sizeof(sock352_fragment_t), 0, (struct sockaddr *)&conn->dest, sizeof(conn->dest)) < 0) {
      printf("Eorror in sending FIN packet");
      return SOCK352_FAILURE;
    }
    __sock352_destroy_fragment(FIN_frag);
    printf("FIN sent\n");
    pthread_cond_wait(&conn->close, &conn->lock);
    pthread_mutex_unlock(&conn->lock);
  }
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
  while (1) {
    pthread_mutex_lock(&conn->lock);
    if (conn->recv_list != NULL) {
      /*copy data to buffer*/
      sock352_fragment_t *frag = conn->recv_list;
      ret = frag->header.payload_len;
      memcpy(buf, frag->data, ret);
      DL_DELETE(conn->recv_list, frag);
      __sock352_destroy_fragment(frag);
      pthread_mutex_unlock(&conn->lock);
      break;
    }
    pthread_mutex_unlock(&conn->lock);
    sleep(1);
  }

  /* Return from the read call. */
  return ret;
}

int sock352_write(int fd, void *buf, int count)
{
  int ret;
  sock352_connection_t * conn;
  sock352_fragment_t *frag;
  
  HASH_FIND_INT(all_connections, &fd, conn);
  pthread_mutex_lock(&conn->lock);
  /* if the window is full, block for signal */
  if (conn->nextseqnum == conn->base+conn->window_size) {
    pthread_cond_wait(&conn->base_change, &conn->lock);
  }
  frag = __sock352_create_fragment();
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
  pthread_mutex_unlock(&conn->lock);
  ret = count;
  return ret;
}


/* receiver thread for client and server*/
void *receiver(void* arg)
{
  int fd = *((int*)arg);
  sock352_connection_t *conn;
  struct sockaddr_in remote_addr;
  socklen_t remote_len;
  sock352_fragment_t *frag;
  sock352_fragment_t *del;
  int close_flag = 0;
  
  HASH_FIND_INT(all_connections, &fd, conn);
  remote_len = sizeof(remote_addr);
  while (1) {
    pthread_mutex_lock(&conn->lock);
    if (close_flag == 1 && conn->send_list == NULL && conn->recv_list == NULL) {
      pthread_cond_signal(&conn->close);
      pthread_mutex_unlock(&conn->lock);
      pthread_exit(NULL);
    }
    else {
      if (recvfrom(master_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&remote_addr, &remote_len) == -1) {
        perror("Eorror in receiving packet\n");
      }
      else {
        frag = __sock352_create_fragment();
        __sock352_copy_buffer(frag);
        if (frag->header.flags == 0 && __sock352_verify_checksum(frag) && frag->header.sequence_no == conn->expectedseqnum) {
          printf("received packet\n");
          DL_APPEND(conn->recv_list, frag);
          __sock352_send_ack(conn);
          conn->expectedseqnum++;
        }
        else if (frag->header.flags == SOCK352_ACK) {
          printf("received ack\n");
          del = conn->send_list;
          DL_DELETE(conn->send_list, del);
          __sock352_destroy_fragment(del);
          conn->base++;
          if (conn->base != conn->nextseqnum)
            __sock352_timer_init(arg);
          __sock352_destroy_fragment(frag);
          pthread_cond_signal(&conn->base_change);
        }
        else if (frag->header.flags == SOCK352_FIN) {
          close_flag = 1;
          __sock352_destroy_fragment(frag);
        }
        else {
          __sock352_destroy_fragment(frag);
        }
      }
    }
    pthread_mutex_unlock(&conn->lock);
  }
}

void * timer(void * arg)
{
  int fd;
  sock352_connection_t *conn;
  uint64_t current_time;
  
  fd = *((int*)arg);
  HASH_FIND_INT(all_connections, &fd, conn);
  while (1) {
    pthread_mutex_lock(&conn->lock);
    if (conn->base == conn->nextseqnum) {
      pthread_mutex_unlock(&conn->lock);
      pthread_exit(NULL);
    }
    /* when timeout event occurs */
    current_time = __sock352_get_timestamp();
    if (current_time - conn->send_list->timestamp > conn->timeout) {
      __sock352_send_expired_fragments(conn);
    }
    pthread_mutex_unlock(&conn->lock);
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
  pthread_mutex_init(&conn->lock, NULL);
  pthread_cond_init(&conn->base_change, NULL);
  pthread_cond_init(&conn->close, NULL);
  HASH_ADD_INT(all_connections, sock352_fd, conn);
  return conn;
}

void __sock352_destroy_connection(sock352_connection_t * conn)
{
  HASH_DEL(all_connections, conn);
  pthread_mutex_destroy(&conn->lock);
  pthread_cond_destroy(&conn->base_change);
  pthread_cond_destroy(&conn->close);
  free(conn);
}

sock352_fragment_t * __sock352_create_fragment()
{
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  bzero(frag, sizeof(sock352_fragment_t));
  frag->header.version = 0x01;
  frag->header.protocol = 0;
  frag->header.opt_ptr = 0;
  frag->header.source_port = 0;
  frag->header.dest_port = 0;
  frag->header.header_len = sizeof(sock352_pkt_hdr_t);
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
  __sock352_destroy_fragment(frag);
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
  /* one's complement
  int len = fragment->header.payload_len;
  uint32_t sum = 0;
  uint16_t *buf = (uint16_t *)fragment->data;
  while(len > 1){
    sum += *buf++;
    if(sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }
  
  if(len)
    sum += (uint16_t) *(uint32_t *)buf;
  
  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
  */
  return 0;
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

void __sock352_copy_buffer(sock352_fragment_t * fragment)
{
  memcpy(fragment, buffer, fragment->header.header_len);
  memcpy(fragment, buffer+fragment->header.header_len, fragment->header.payload_len);
  bzero(buffer, BUFFER_SIZE);
}





