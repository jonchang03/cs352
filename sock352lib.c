/* sock3532lib.c */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sock352lib.h>
#include <sock352.h>
#include <uthash.h>

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

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
	struct sockaddr_in tmpaddr;
	memset((char *)&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = addr->sin_family;
	tmpaddr.sin_port = addr->sin_port;
	tmpaddr.sin_addr.s_addr = addr->sin_addr.s_addr;
	return bind(fd, (struct sockaddr *)&tmpaddr, sizeof(tmpaddr));
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len)
{
	struct sockaddr_in tmpaddr;
	memset((char *)&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = addr->sin_family;
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
	int length = 0;
	memset((char *)&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = addr->sin_family;
	tmpaddr.sin_port = addr->sin_port;
	tmpaddr.sin_addr.s_addr = addr->sin_addr.s_addr;
	length = sizeof(tmpaddr);
	len = &length;
	return accept(fd, (struct sockaddr *)&tmpaddr, len);
}

int sock352_close(int fd)
{
  return close(fd);
}
int sock352_read(int fd, void *buf, int count)
{
  return read(fd, buf, count);
}
int sock352_write(int fd, void *buf, int count)
{
  return write(fd, buf, count);
}
