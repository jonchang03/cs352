#ifndef SOCK352LIB_H
<<<<<<< HEAD
#define SOCK352LIB_H 1

#include "uthash.h"
#include "utlist.h"
=======
#define SOCK352LIB_H

#include "sock352.h"
>>>>>>> 0376363025f4ecfcb62670d73937fd493a9c7caf
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include "sock352.h"

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

  pthread_mutex_t lock;          /* mutex locks to access the connection */
  struct sock352_fragment * fragments;     /* list of fragments */
  struct sock352_connection *next;
  struct sock352_connection *prev;

  unsigned int source_port;
  unsigned int dest_port;
  unsigned int next_seqNum;
  struct sock352_fragment *noAckButTransmt_frags;
  struct sock352_fragment *recvd_frags;

<<<<<<< HEAD
=======
  struct sock352_fragment * fragments;    /* list of fragments */
  struct sock352_connection *next;        /* list of connections */
  struct sock352_connection *prev;  
  
  uint32_t local_port;                    /* sockets for local and remote ports */
  uint32_t remote_port;
  uint16_t src_port;                      /* source and destination UDP ports */
  uint16_t dest_port;

  uint64_t timeout;
  uint64_t ACK;                           /* sent and acknowledged */
  uint64_t NAK;                           /* sent and unacknowledged */
  uint64_t MAX;                           /* maximum we can send */ 
>>>>>>> 0376363025f4ecfcb62670d73937fd493a9c7caf

  unsigned int sock352_fd;
  UT_hash_handle hh;
}sock352_connection_t;

typedef struct sock352_fragment {
  struct sock352_connection *connection;
  unsigned int size;
  sock352_pkt_hdr_t header;
  char data[MAXIMUM_LENGTH];
  struct sock352_fragment *next;
  struct sock352_fragment *prev;
}sock352_fragment_t;

struct sock352_GLOBAL {
  sock352_connection_t *active_connections;
  unsigned int sock352_recv_port;
  unsigned int sock352_base_fd;
}_GLOABAL;

#endif
