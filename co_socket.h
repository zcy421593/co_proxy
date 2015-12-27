#ifndef CO_SOCKET_H
#define CO_SOCKET_H
#include "co_base.h"

struct co_socket;
void co_socket_error_all();
struct co_socket* co_socket_create(co_base*);
struct co_socket* co_socket_create_with_fd(co_base*, int fd);
int co_socket_connect(co_socket*, const char* addr, int port);
void co_socket_set_readtimeout(co_socket* sock, int ms);
int co_socket_bind(co_socket*, const char* addr, int port);
int co_socket_listen(co_socket* sock, int backlog);
co_socket* co_socket_accept(co_socket* sock);
int co_socket_read(co_socket* sock, char* buf, int len);
int co_socket_read_peek(co_socket* sock, char* buf, int len);
int co_socket_readline(co_socket* sock, char* buf, int len);
int co_socket_write(co_socket* sock, char* buf, int len);
int co_socket_detach_fd(co_socket* sock);
int co_socket_get_fd(co_socket* sock);
void co_socket_close(co_socket* sock);
bool co_socket_is_error(co_socket* sock);
#endif
