/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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

int sock352_socket(int domain, int type, int protocol)
{
  /* ensure that the domain and type are correct */
  if (domain != AF_CS352) {
    return SOCK352_FAILURE;
  }
  if (type != SOCK_STREAM) {
    return SOCK352_FAILURE;
  }
  sock352_connection_t *conn = malloc(sizeof(sock352_connection_t));
  bzero(conn, sizeof(sock352_connection_t));
  master_fd = socket(domain, SOCK_DGRAM, protocol);
  conn->sock352_fd = sock352_fd_base++;
  pthread_mutex_init(&conn->lock, NULL);
  HASH_ADD_INT(all_connections, sock352_fd, conn);
  return conn->sock352_fd;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  conn->src_addr = addr->sin_addr;
  conn->src_port = addr->sin_port;
  return SOCK352_SUCCESS;
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
  struct timeval timeout={0,2};
  if (setsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    perror("fail to setsockopt");
    exit(-1);
  }
  
  /* the real remote socket address */
  sockaddr_sock352_t *real_addr = malloc(sizeof(sockaddr_sock352_t));
  real_addr->sin_addr = addr->sin_addr;
  real_addr->sin_port = sock352_remote_port;
  socklen_t real_len= sizeof(real_addr);
  
  /* set up connection */
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  conn->dest_addr = addr->sin_addr;
  conn->dest_port = addr->sin_port;
  conn->base = 0;
  conn->nextseqnum = 0;
  conn->window_size = WINDOW_SIZE;
  conn->timeout = 0.2 * (uint64_t)(1000000);
  
 /* set up first SYN segment */
  sock352_fragment_t *SYN_frag = __sock352_create_fragment();
  srand((unsigned int)(time(NULL)));
  SYN_frag->header->sequence_no = rand();
  SYN_frag->header->ack_no = 0;
  SYN_frag->header->flags = SOCK352_SYN;
  
  /* send SYN packet */
  if (sendto(master_fd, (char *)SYN_frag, sizeof(SYN_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
    printf("Eorror in sending SYN packet");
    return SOCK352_FAILURE;
  }
  
  /* receive SYNACK segment */
  sock352_fragment_t *SYNACK_frag = __sock352_create_fragment();
  while (1) {
    if (recvfrom(master_fd, (char *)SYNACK_frag, sizeof(SYNACK_frag), 0, (struct sockaddr *)real_addr, &real_len) < 0) {
      /* timeout occurs, resend */
      if (errno == EAGAIN) {
        if (sendto(master_fd, (char *)SYN_frag, sizeof(SYN_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
          printf("Eorror in sending SYN packet");
          return SOCK352_FAILURE;
        }
      }
    }
    else {
      /* acknowledgement number is wrong, resend */
      if (SYNACK_frag->header->ack_no != SYN_frag->header->sequence_no + 1 || SYNACK_frag->header->flags != (SOCK352_ACK | SOCK352_SYN)) {
        printf("Eorror in received SYNACK packet");
        if (sendto(master_fd, (char *)SYN_frag, sizeof(SYN_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
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
  ACK_frag->header->sequence_no = SYN_frag->header->sequence_no;
  ACK_frag->header->ack_no = SYNACK_frag->header->sequence_no + 1;
  ACK_frag->header->flags = SOCK352_ACK;
  
  /* send the third segment */
  if (sendto(master_fd, (char *)SYN_frag, sizeof(SYN_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
    printf("Eorror in sending ACK packet");
    return SOCK352_FAILURE;
  }
  
  /* create lists */
  conn->send_list = NULL;
  conn->recv_list = NULL;
 
  free(real_addr);
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
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  conn->dest_addr = addr->sin_addr;
  conn->dest_port = addr->sin_port;
  
  /* the real remote socket address */
  sockaddr_sock352_t *real_addr = malloc(sizeof(sockaddr_sock352_t));
  real_addr->sin_addr = addr->sin_addr;
  real_addr->sin_port = sock352_remote_port;
  socklen_t real_len= sizeof(real_addr);
  
  /* receive SYN packet */
  sock352_fragment_t *SYN_frag = __sock352_create_fragment();
  while (1) {
    if (recvfrom(master_fd, (char *)SYN_frag, sizeof(SYN_frag), 0, (struct sockaddr *)real_addr, &real_len) < 0) {
      printf("Error in receiving SYN packet");
    }
    else {
      if (SYN_frag->header->flags == SOCK352_SYN) {
        break;
      }
    }
    bzero(SYN_frag, sizeof(sock352_fragment_t));
  }
  
  sock352_connection_t *new_conn;
  new_conn->sock352_fd = sock352_fd_base++;
  new_conn->dest_addr = conn->dest_addr;
  new_conn->dest_port = conn->dest_port;
  pthread_mutex_init(&new_conn->lock, NULL);
  HASH_ADD_INT(all_connections, sock352_fd, new_conn);
  
  /* set up SYN/ACK segment */
  sock352_fragment_t *SYNACK_frag = __sock352_create_fragment();
  srand((unsigned int)(time(NULL)));
  SYNACK_frag->header->sequence_no = rand();
  SYNACK_frag->header->ack_no = SYN_frag->header->sequence_no + 1;
  SYNACK_frag->header->flags = SOCK352_ACK | SOCK352_SYN;
  
  struct timeval timeout={0,2};
  if (setsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    perror("fail to setsockopt");
    exit(-1);
  }
  
  /* return a SYSACK flagged packet */
  if (sendto(master_fd, (char *)SYNACK_frag, sizeof(SYNACK_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
    printf("Eorror in sending SYNACK packet");
    return SOCK352_FAILURE;
  }
  
  sock352_fragment_t *ACK_frag = __sock352_create_fragment();
  while (1) {
    if (recvfrom(master_fd, (char *)ACK_frag, sizeof(ACK_frag), 0, (struct sockaddr *)real_addr, &real_len) < 0) {
      /* timeout occurs, resend */
      if (errno == EAGAIN) {
        if (sendto(master_fd, (char *)SYNACK_frag, sizeof(SYNACK_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
          printf("Eorror in sending SYNACK packet");
          return SOCK352_FAILURE;
        }
      }
    }
    else {
      /* acknowledgement number is wrong, resend */
      if (ACK_frag->header->ack_no != SYNACK_frag->header->sequence_no + 1 || ACK_frag->header->flags != (SOCK352_ACK | SOCK352_SYN)) {
        printf("Eorror in received ACK packet");
        if (sendto(master_fd, (char *)SYNACK_frag, sizeof(SYNACK_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
          printf("Eorror in sending SYNACK packet");
          return SOCK352_FAILURE;
        }
      }
      else
        break;
    }
  }
  
  free(real_addr);
  __sock352_destroy_fragment(SYN_frag);
  __sock352_destroy_fragment(SYNACK_frag);
  __sock352_destroy_fragment(ACK_frag);
  
  new_conn->expectedseqnum = 0;
  /* create empty lists of fragments to receive */
  new_conn->send_list = NULL;			/* important to initialize header to NULL! */
  new_conn->recv_list = NULL;
  
  __sock352_receiver_init(&fd);
  /* return from accept() call */
  return new_conn->sock352_fd;
}

int sock352_close(int fd)
{
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  /* the real remote socket address */
  sockaddr_sock352_t *real_addr = malloc(sizeof(sockaddr_sock352_t));
  real_addr->sin_addr = conn->dest_addr;
  real_addr->sin_port = sock352_remote_port;
  socklen_t real_len= sizeof(real_addr);
  
  struct timeval timeout={0,2};
  if (setsockopt(master_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    perror("fail to setsockopt");
    exit(-1);
  }
  
  sock352_fragment_t *FIN1_frag = __sock352_create_fragment();
  FIN1_frag->header->flags = SOCK352_FIN;
  
  if (sendto(master_fd, (char *)FIN1_frag, sizeof(FIN1_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
    printf("Eorror in sending FIN packet");
    return SOCK352_FAILURE;
  }
  
  sock352_fragment_t *FIN2_frag = __sock352_create_fragment();
  while (1) {
    if (recvfrom(master_fd, (char *)FIN2_frag, sizeof(FIN2_frag), 0, (struct sockaddr *)real_addr, &real_len) < 0) {
      /* timeout occurs, resend */
      if (errno == EAGAIN) {
        if (sendto(master_fd, (char *)FIN1_frag, sizeof(FIN1_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
          printf("Eorror in resending FIN packet");
          return SOCK352_FAILURE;
        }
      }
    }
    else {
      if (FIN2_frag->header->flags != SOCK352_FIN) {
        printf("Eorror in received FIN packet");
        if (sendto(master_fd, (char *)FIN1_frag, sizeof(FIN1_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
          printf("Eorror in resending FIN packet");
          return SOCK352_FAILURE;
        }
      }
      else
        break;
    }
  }
  
  sock352_fragment_t *ACK1_frag = __sock352_create_fragment();
  FIN1_frag->header->flags = SOCK352_ACK;
  
  if (sendto(master_fd, (char *)ACK1_frag, sizeof(ACK1_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
    printf("Eorror in sending ACK packet");
    return SOCK352_FAILURE;
  }
  
  sock352_fragment_t *ACK2_frag = __sock352_create_fragment();
  while (1) {
    if (recvfrom(master_fd, (char *)ACK2_frag, sizeof(ACK2_frag), 0, (struct sockaddr *)real_addr, &real_len) < 0) {
      /* timeout occurs, resend */
      if (errno == EAGAIN) {
        if (sendto(master_fd, (char *)ACK1_frag, sizeof(ACK1_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
          printf("Eorror in resending ACK packet");
          return SOCK352_FAILURE;
        }
      }
    }
    else {
      if (ACK2_frag->header->flags != SOCK352_ACK) {
        printf("Eorror in received ACK packet");
        if (sendto(master_fd, (char *)ACK1_frag, sizeof(ACK1_frag), 0, (struct sockaddr *)real_addr, real_len) < 0) {
          printf("Eorror in resending ACK packet");
          return SOCK352_FAILURE;
        }
      }
      else
        break;
    }
  }
  free(real_addr);
  __sock352_destroy_fragment(FIN1_frag);
  __sock352_destroy_fragment(FIN2_frag);
  __sock352_destroy_fragment(ACK1_frag);
  __sock352_destroy_fragment(ACK2_frag);
  
  /* all fragments are reveived*/

  return SOCK352_SUCCESS;
}

int sock352_read(int fd, void *buf, int count)
{
  int ret;
  sock352_connection_t * conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  /* Lock the connection */
  pthread_mutex_lock (&conn->lock);
  
  sock352_fragment_t *elt;
  int frag_count;
  DL_COUNT(conn->recv_list, elt, frag_count);
  
  while (1) {
    if (frag_count != 0) {
      /*copy data to buffer*/
      sock352_fragment_t *frag;
      DL_DELETE(conn->recv_list, frag);
      ret = frag->header->payload_len;
      memcpy(buf, frag->data, ret);
      __sock352_destroy_fragment(frag);
      pthread_mutex_unlock (&conn->lock);
      break;
    }
    else {
      pthread_mutex_unlock (&conn->lock);
      sleep(1);
      pthread_mutex_lock (&conn->lock);
    }
  }
  /* Return from the read call. */
  return ret;
}

int sock352_write(int fd, void *buf, int count)
{
  /* find the connection in hash table */
  ssize_t ret;
  sock352_connection_t * conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  /* use mutex to lock the connection */
  pthread_mutex_lock (&conn->lock);

  /* the real remote socket address */
  sockaddr_sock352_t *real_addr = malloc(sizeof(sockaddr_sock352_t));
  real_addr->sin_addr = conn->dest_addr;
  real_addr->sin_port = sock352_remote_port;
  socklen_t real_len= sizeof(real_addr);
  
  while (1) {
    /* if the window is not full */
    if (conn->nextseqnum < conn->base+conn->window_size) {
      sock352_fragment_t *frag = __sock352_create_fragment();
      /* include data */
      frag->data = buf;
      /* set up header */
      frag->header->flags = 0;
      frag->header->payload_len = count;
      __sock352_compute_checksum(frag);
      frag->header->sequence_no = conn->nextseqnum;
      frag->timestamp = __sock352_get_timestamp();
      
      /* apeend to send list */
      DL_APPEND(conn->send_list, frag);
      
      if ((ret = sendto(master_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)real_addr, real_len)) < 0) {
        printf("Eorror in sending packet");
        return SOCK352_FAILURE;
      }
      
      if (conn->base == conn->nextseqnum) {
        __sock352_timeout_init(&fd);
      }
      conn->nextseqnum++;
      pthread_mutex_unlock (&conn->lock);
      break;
    }
    else {
      pthread_mutex_unlock (&conn->lock);
      sleep(1);
      pthread_mutex_lock (&conn->lock);
    }
  }
  
  free(real_addr);
  return (int)ret;
}


/* receiver thread for client and server*/
void *receiver(void* arg)
{
  int fd = *((int*)arg);
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  sockaddr_sock352_t addr;
  socklen_t len= sizeof(addr);
  while (1) {
    sock352_fragment_t *frag = __sock352_create_fragment();
    bzero(frag, sizeof(sock352_fragment_t));
    if (recvfrom(conn->sock352_fd, (char *)frag, sizeof(frag), 0, (struct sockaddr *)&addr, &len) < 0) {
      pthread_exit(NULL);
    }
    if (frag->header->flags == 0) {
      DL_APPEND(conn->recv_list, frag);
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
  int fd = *((int*)arg);
  sock352_connection_t *conn;
  HASH_FIND_INT(all_connections, &fd, conn);
  
  while (1) {
    pthread_mutex_lock(&conn->lock);
    uint64_t current_time = __sock352_get_timestamp();
    
    /* when timeout event occurs */
    if (current_time - conn->send_list->timestamp > conn->timeout) {
      __sock352_send_expired_fragments(conn);
    }
    
    /* when send buffer is empty, terminate this thread */
    if (conn->base == conn->nextseqnum) {
      pthread_mutex_unlock(&conn->lock);
      pthread_exit(NULL);
    }
    pthread_mutex_unlock(&conn->lock);
  }
}


/* Internal Functions */
void __sock352_receiver_init(void *arg)
{
  pthread_t thread;
  pthread_create(&thread, NULL, receiver, arg);
}

void __sock352_timeout_init(void *arg)
{
  pthread_t thread;
  pthread_create(&thread, NULL, timer, arg);
}


sock352_fragment_t * __sock352_create_fragment()
{
  sock352_fragment_t *frag = malloc(sizeof(sock352_fragment_t));
  bzero(frag, sizeof(sock352_fragment_t));
  frag->header = malloc(sizeof(sock352_pkt_hdr_t));
  bzero(frag->header, sizeof(sock352_pkt_hdr_t));
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

int __sock352_send_expired_fragments(sock352_connection_t *conn)
{
  /* the real remote socket address */
  sockaddr_sock352_t *real_addr = malloc(sizeof(sockaddr_sock352_t));
  real_addr->sin_addr = conn->dest_addr;
  real_addr->sin_port = sock352_remote_port;
  socklen_t real_len= sizeof(real_addr);
  
  /* resend every fragment in the send list, and reset their timestamp */
  sock352_fragment_t *elt;
  DL_FOREACH(conn->send_list, elt) {
    if (sendto(conn->sock352_fd, (char *)elt, sizeof(elt), 0, (struct sockaddr *)real_addr, real_len) < 0) {
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





