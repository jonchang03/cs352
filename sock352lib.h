#ifndef SOCK352LIB_H
#define SOCK352LIB_H

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

  uint32_t sock352_fd;                    /* file descriptor */
  uint32_t state;                         /* holds state of the connection (open, connected, waiting) */

  pthread_mutex_t lock;                   /* mutex locks to access the connection */

  struct sock352_fragment * fragments;    /* list of fragments */
  struct sock352_connection *next;        /* list of connections */
  struct sock352_connection *prev;  
  
  uint32_t local_port;                    /* sockets for local and remote ports */
  uint32_t remote_port;
  uint16_t src_port;                      /* source and destination UDP ports */
  uint16_t dest_port;

  uint64_t timeout;
  uint64_t ACK;                           /* sent and acknowledged */
  uint64_t UNACK;                         /* sent and unacknowledged */
  uint64_t MAX;                           /* maximum we can send */ 

}sock352_connection_t;

typedef struct sock352_fragment {
  struct sock352_connection *connection;  /* connection for the fragment */
  uint32_t size;                          /* size of the fragment in bytes */
  uint32_t next;                          /* index for next data */
  uint64_t seq_start;                     /* start sequence number */
  uint64_t timestamp;                     /* time sent or received */

  struct sock352_fragment *next;          /* list of fragments for each connection */
  struct sock352_fragment *prev;
}sock352_fragment_t;

struct sock352_GLOBAL {
  sock352_connection_t *active_connections;
  unsigned int sock352_recv_port;
  unsigned int sock352_base_fd;
}_GLOABAL;

#endif
