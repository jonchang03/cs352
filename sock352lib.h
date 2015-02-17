#include <sock352.h>
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

typedef struct cs352_connection {


}

  typedef struct cs352_fragment {
    unsigned int state;
    unsigned int portNum;

  }fragment;
