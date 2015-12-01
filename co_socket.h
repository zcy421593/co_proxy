#ifndef CO_SOCKET_H
#define CO_SOCKET_H
#include "co_base.h"

struct co_socket;
struct co_socket* co_socket_create(co_base*);
int co_socket_connect(co_socket*, const char* addr, int port);
int co_socket_bind(co_socket*, const char* addr, int port);
int co_socket_listen(co_socket* sock, int backlog);
co_socket* co_socket_accept(co_socket* sock);
int co_socket_read(co_socket* sock, char* buf, int len);
int co_socket_readline(co_socket* sock, char* buf, int len);
int co_socket_write(co_socket* sock, char* buf, int len);
#endif
