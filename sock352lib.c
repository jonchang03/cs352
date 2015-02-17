#include <sock352lib.h>

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


int sock352_init(int udp_port)
{
  if (udp_port != 0) {
    return SOCK352_FAILURE;
  } else {
    connection = malloc(sizeof(CB));
    connection->portNum = SOCK352_DEFAULT_UDP_PORT;
    return SOCK352_SUCCESS;
  }
}

int sock352_socket(int domain, int type, int protocol)
{
	return socket(domain, type, protocol);
}

int sock352_bind(int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
	struct sockaddr_in tmpaddr;
	memset((char *)&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = addr->sin_family;;
	tmpaddr.sin_port = addr->sin_port;
	tmpaddr.sin_addr.s_addr = addr->sin_addr.s_addr;
	return bind(fd, (struct sockaddr *)&tmpaddr, sizeof(tmpaddr));
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
	struct sockaddr_in tmpaddr;
	memset((char *)&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = addr->sin_family;;
	tmpaddr.sin_port = addr->sin_port;
	tmpaddr.sin_addr.s_addr = addr->sin_addr.s_addr;
        return connect(fd, (struct sockaddr *)&tmpaddr, sizeof(tmpaddr));
}

int sock352_listen(int fd, int n)
{
  return listen(fd, n);
}
int sock352_accept(int fd, sockaddr_sock352_t *addr, int *len)
{
	struct sockaddr_in tmpaddr;
	memset((char *)&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = addr->sin_family;;
	tmpaddr.sin_port = addr->sin_port;
	tmpaddr.sin_addr.s_addr = addr->sin_addr.s_addr;
	return accept(fd, (struct sockaddr *)&tmpaddr, sizeof(tmpaddr));
}

int sock352_close(int fd)
{
  return close(fd);)
}
int sock352_read(int fd, void *buf, int count)
{
  return read(fd, buf, count);
}
int sock352_write(int fd, void *buf, int count)
{
  return write(fd, buf, count);
}
