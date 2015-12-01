#include "co_socket.h"
#include "coroutine.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
struct co_socket {
	int fd;
	co_base* base;
	int task_id_read;
	int task_id_write;
	event* event_read;
	event* event_write;
	int read_timeout;
	int write_timeout;
};

struct co_socket* co_socket_create(co_base* base) {
	co_socket* sock = (co_socket*)calloc(1, sizeof(co_socket));
	sock->base = base;
	sock->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sock->read_timeout = -1;
	sock->write_timeout = -1;
	evutil_make_socket_nonblocking(sock->fd);
	return sock;
};

int co_socket_connect(co_socket*, const char* addr, int port) {
	return 0;
}

int co_socket_bind(co_socket* sock, const char* str_addr, int port) {
	int reuse = 1;
	sockaddr_in addr = {};
	addr.sin_addr.s_addr = inet_addr(str_addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	return bind(sock->fd, (sockaddr*)&addr, sizeof(addr));
}

int co_socket_listen(co_socket* sock, int backlog) {
	return listen(sock->fd, backlog);
}

static void acceptcb(int fd, short what, void* args) {
	co_socket* sock = (co_socket*)args;
	coroutine_resume(sock->base->sch, sock->task_id_read);
}

static void writecb(int fd, short what, void* args) {
	co_socket* sock = (co_socket*)args;
	coroutine_resume(sock->base->sch, sock->task_id_write);
}

static void readcb(int fd, short what, void* args) {
	co_socket* sock = (co_socket*)args;
	coroutine_resume(sock->base->sch, sock->task_id_read);
}

co_socket* co_socket_accept(co_socket* sock) {
	co_socket* sock_ret = NULL;
	if(!sock->event_read) {
		sock->event_read = event_new(sock->base->base, sock->fd, EV_READ, acceptcb, sock);
	}	
	sock->task_id_read = coroutine_running(sock->base->sch);
	event_add(sock->event_read, NULL);
	coroutine_yield(sock->base->sch);
	int fd = accept(sock->fd, NULL, NULL);
	evutil_make_socket_nonblocking(fd);
	if(fd < 0) {
		return NULL;
	}

	sock_ret = (co_socket*)calloc(1, sizeof(co_socket));
	sock_ret->fd = fd;
	sock_ret->base = sock->base;
	return sock_ret;
}

int co_socket_read(co_socket* sock, char* buf, int len) {
	if(!sock->event_read) {
		sock->event_read = event_new(sock->base->base, sock->fd, EV_READ, readcb, sock);
	}

	sock->task_id_read = coroutine_running(sock->base->sch);
	event_add(sock->event_read, NULL);
	coroutine_yield(sock->base->sch);
	return recv(sock->fd, buf, len, 0);
}

int co_socket_readline(co_socket* sock, char* buf, int len) {
	memset(buf, 0, len);
	if(!sock->event_read) {
		sock->event_read = event_new(sock->base->base, sock->fd, EV_READ, readcb, sock);
	}


	sock->task_id_read = coroutine_running(sock->base->sch);

	for(;;) {
		event_add(sock->event_read, NULL);
		coroutine_yield(sock->base->sch);
		int len_in_readbuf = recv(sock->fd, buf, len - 1, MSG_PEEK);

		if(len_in_readbuf <= 0) {
			return -1;
		}
		
		char* pos = strstr(buf, "\r\n");
		if(pos) {
			int len_line = pos - buf;
			recv(sock->fd, buf, len_line + 2, 0);
			buf[len_line] = '\0';
			return len_line;
		} else if(len_in_readbuf >= len - 1) {
			return -1;
		}
	}
}

int co_socket_write(co_socket* sock, char* buf, int len) {
	const int write_len_once = 4096;
	
	int write_len = 0;
	for(;;) {
		int len_to_write = len - write_len < write_len_once ? len - write_len : write_len_once;
		int len_real_write = send(sock->fd, buf + write_len, len_to_write, 0);

		if(len_real_write < 0) {
			if(errno == EINPROGRESS) {
				if(!sock->event_write) {
					sock->event_write = event_new(sock->base->base, sock->fd, EV_WRITE, writecb, sock);
				}
				event_add(sock->event_write, NULL);
				sock->task_id_write = coroutine_running(sock->base->sch);
				coroutine_yield(sock->base->sch);
				continue;
			} else {
				break;
			}
		}
		write_len += len_real_write;
		if(len_real_write < len_to_write) {
			if(!sock->event_write) {
				sock->event_write = event_new(sock->base->base, sock->fd, EV_WRITE, acceptcb, sock);
			}
			sock->task_id_write = coroutine_running(sock->base->sch);
			event_add(sock->event_write, NULL);
			coroutine_yield(sock->base->sch);
			continue;
		}

		if(write_len == len) {
			break;
		}

	}
	

	return write_len;
}
