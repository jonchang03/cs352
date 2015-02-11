#include <sock352.h>

sockaddr_sock352_t *sockaddr;


int sock352_init(int udp_port)
{
	sockaddr->sin_port = udp_port;
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
int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len)
{

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
