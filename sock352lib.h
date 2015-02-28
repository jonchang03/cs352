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

typedef struct sock352_connection {
  uint32_t state;

  pthread_mutex_t lock_connection;        /* mutex locks to access the connection */

  struct sock352_fragment *noAckButTransmt_frags;
  struct sock352_fragment *recvd_frags;

  struct sock352_fragment * frag_list;    /* transmit list of fragments */
  struct sock352_connection *next;        /* list of connections */
  struct sock352_connection *prev;

  uint32_t local_port;                    /* sockets for local and remote ports */
  uint32_t remote_port;
  uint16_t src_port;                      /* source and destination UDP ports */
  uint16_t dest_port;
  struct in_addr src_addr;
  struct in_addr dest_addr;

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

typedef struct sock352_fragment {
  struct sock352_connection *connection;
  uint32_t size;
  sock352_pkt_hdr_t *header;
  uint8_t *data;
  uint64_t timestamp;
  struct sock352_fragment *next;
  struct sock352_fragment *prev;
}sock352_fragment_t;

typedef struct sock352_global {            /* global structure for all connections */
  sock352_connection_t *active_connections;
  unsigned int sock352_recv_port;
  unsigned int sock352_base_fd;
}sock352_global_t;

sock352_global_t *global_p = NULL;


/* Internal Functions */
int __sock352_init(int remote_port, int local_port);
void __sock352_reader_init(void *ptr);
void __sock352_timeout_init(void *ptr);
int __sock352_input_packet(sock352_global_t *global_p);
int __sock352_send_fragment(sock352_connection_t *connection,sock352_fragment_t *fragment); 
int __sock352_send_ack(sock352_connection_t *connection);
int __sock352_send_expired_fragments(sock352_connection_t *connection); 
sock352_connection_t * __sock352_find_active_connection(sock352_global_t *global_p, int fd); 
sock352_connection_t * __sock352_find_accept_connection(sock352_global_t *global_p, sock352_pkt_hdr_t *pkt_hdr);
int __sock352_connection_return(sock352_global_t *global_p, sock352_pkt_hdr_t * pkt_hdr, sock352_connection_t *connection);
int __sock352_accept_return(sock352_pkt_hdr_t *pkt_rx_hdr,sock352_connection_t *connection);
uint64_t __sock352_lapsed_usec(struct timeval * start, struct timeval *end);
int __sock352_add_tx_fragment(sock352_connection_t *connection, sock352_fragment_t *fragment); 
int __sock352_remove_tx_fragment(sock352_connection_t * active_connection,sock352_fragment_t *fragment);
int __sock352_enqueue_data_packet(sock352_connection_t *connection,uint8_t *data, int header_size, int data_size);
int __sock352_add_rx_fragment(sock352_connection_t *connection, sock352_fragment_t *fragment);


#endif
