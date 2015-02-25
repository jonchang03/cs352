#include "sock352.h"
#include <stdlib.h>

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
  unsigned int state;
  unsigned int source_port;
  unsigned int dest_port;
  unsigned int next_seqNum;
  struct sock352_fragment *noAckButTransmt_frags;
  struct sock352_fragment *recvd_frags;
  struct sock352_connection *next;
  struct sock352_connection *prev;
  int sock352_fd;
}sock352_connection_t;

typedef struct sock352_fragment {
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
