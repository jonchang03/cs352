/* sock352lib.h */
#ifndef SO3CK352LIB_H
#define SOCK352LIB_H 1

#include "uthash.h"
#include "utlist.h"
#include "sock352.h"
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>

#define CLOSED 1
#define SYN_SENT 2
#define ESTABLISHED 3
#define FIN_WAIT_1 4
#define FIN_WAIT_2 5
#define TIME_WAIT 6
#define LISTEN 7
#define SYN_RCVD 8
#define CLOSE_WAIT 9
#define LAST_ACK 10

#define WINDOW_SIZE 5;
#define BUFSIZE 8192

typedef struct sock352_fragment {
  sock352_pkt_hdr_t header;
  uint8_t data[BUFSIZE];
  uint64_t timestamp;
  struct sock352_fragment *next;
  struct sock352_fragment *prev;
}sock352_fragment_t;

typedef struct sock352_connection {
  pthread_mutex_t lock;        /* mutex locks to access the connection */
  
  struct sock352_fragment *send_list;    /* transmit list of fragments */
  struct sock352_fragment *recv_list;
  struct sock352_connection *next;        /* list of connections */
  struct sock352_connection *prev;
  
  struct sockaddr_in src;
  struct sockaddr_in dest;
  
  uint64_t timeout;
  
  // used by client
  uint64_t base;                          /* the sequence number of the oldest unacknowledged packet */
  uint64_t nextseqnum;                    /* the smallest unused sequence number */
  uint64_t window_size;                   /* maximum we can send */
  
  // used by server
  uint64_t expectedseqnum;                /* the expected sequence number */
  
  uint32_t sock352_fd;
  UT_hash_handle hh;                      /* makes this structure hashable */
}sock352_connection_t;

/* global variables */
uint32_t sock352_fd_base;
uint32_t master_fd;
sock352_connection_t *all_connections;
uint32_t sock352_remote_port;
uint32_t sock352_local_port;



/* Internal Functions */
int __sock352_init(int udp_port);
int sock352_init2(int remote_port, int local_port);
void __sock352_receiver_init(void *ptr);
void __sock352_timeout_init(void *ptr);
sock352_fragment_t * __sock352_create_fragment();
void __sock352_destroy_fragment(sock352_fragment_t *);
int __sock352_send_fragment(sock352_connection_t *connection,sock352_fragment_t *fragment);
int __sock352_send_ack(sock352_connection_t *connection);
int __sock352_send_expired_fragments(sock352_connection_t *connection);
uint64_t __sock352_lapsed_usec(struct timeval * start, struct timeval *end);
void __sock352_compute_checksum(sock352_fragment_t *fragment);
int __sock352_verify_checksum(sock352_fragment_t *fragment);
uint64_t __sock352_get_timestamp();
void *receiver(void* arg);
void * timer(void *conn);

#endif
