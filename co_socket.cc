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
#include <unistd.h>
#include <assert.h>
#include "list.h"

static list_head_t s_head = LIST_HEAD_INIT(s_head);

struct co_socket {
	list_head list;
	int fd;
	co_base* base;
	int read_task_id;
	int write_task_id;
	int accept_task_id;
	event* event_read;
	event* event_write;
	event* event_cancel;
	int read_timeout;
	int write_timeout;
	bool is_task_canceled;
	bool is_read_timeout;
	bool is_write_timeout;
	bool is_error;
};

static void cancelcb(int fd, short what, void* args) {
	co_socket* sock = (co_socket*)args;
	sock->is_task_canceled = true;

	if(sock->read_task_id != -1) {
		coroutine_resume(sock->base->sch, sock->read_task_id);
	}
	if(sock->write_task_id != -1) {
		coroutine_resume(sock->base->sch, sock->write_task_id);
	}
	
}

void co_socket_error_all() {
	co_socket* pos;
	co_socket* tmp;
	list_for_each_entry_safe(pos, tmp, &s_head, list) {
		if((pos->event_read && event_pending(pos->event_read, EV_READ, NULL)) || 
			(pos->event_write && event_pending(pos->event_write, EV_WRITE, NULL))) {
			timeval val = {};
			pos->event_cancel = evtimer_new(pos->base->base, cancelcb, pos);
			event_add(pos->event_cancel, &val);
		}		
	}
}

struct co_socket* co_socket_create(co_base* base) {
	co_socket* sock = (co_socket*)calloc(1, sizeof(co_socket));
	sock->base = base;
	sock->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(sock->fd < 0) {
		assert(0);
	}
	sock->read_timeout = -1;
	sock->write_timeout = -1;
	sock->read_task_id = -1;
	sock->write_task_id = -1;
	sock->accept_task_id = -1;
	evutil_make_socket_nonblocking(sock->fd);
	list_add(&sock->list, &s_head);
	return sock;
};

struct co_socket* co_socket_create_with_fd(co_base* base, int fd) {
	co_socket* sock = (co_socket*)calloc(1, sizeof(co_socket));
	sock->base = base;
	sock->fd = fd;
	sock->read_timeout = -1;
	sock->write_timeout = -1;
	sock->write_task_id = -1;
	sock->read_task_id = -1;
	evutil_make_socket_nonblocking(sock->fd);
	list_add(&sock->list, &s_head);
	return sock;
};


void co_socket_set_readtimeout(co_socket* sock, int ms) {
	printf("co_socket_set_readtimeout:%d\n", ms);
	sock->read_timeout = ms;
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
	printf("acceptcb called\n");
	co_socket* sock = (co_socket*)args;
	int tmp = sock->accept_task_id;
	//sock->read_task_id = -1;
	coroutine_resume(sock->base->sch, tmp);
}

static void conncb(int fd, short what, void* args) {
	printf("conncb called\n");
	co_socket* sock = (co_socket*)args;
	int tmp = sock->write_task_id;
	//sock->write_task_id = -1;
	coroutine_resume(sock->base->sch, tmp);
}

static void writecb(int fd, short what, void* args) {
	printf("writecb called\n");
	co_socket* sock = (co_socket*)args;
	if(what & EV_TIMEOUT) {
		printf("write timeout\n");
		sock->is_write_timeout = true;
	}
	int tmp = sock->write_task_id;
	//sock->write_task_id = -1;
	coroutine_resume(sock->base->sch, tmp);
}

static void readcb(int fd, short what, void* args) {
	printf("readcb called\n");

	
	co_socket* sock = (co_socket*)args;
	if(what & EV_TIMEOUT) {
		printf("read timeout\n");
		sock->is_read_timeout = true;
	}
	int tmp = sock->read_task_id;
	//sock->read_task_id = -1;
	coroutine_resume(sock->base->sch, tmp);
}

void co_socket_set_connecttimeout(co_socket* sock, int ms) {
	sock->write_timeout = ms;
}

void co_socket_cancel(co_socket* sock) {
	timeval val = {};
	if((sock->event_read && event_pending(sock->event_read, EV_READ, NULL)) ||
		(sock->event_write && event_pending(sock->event_write, EV_WRITE, NULL))) {
		sock->is_task_canceled = true;
		sock->event_cancel = evtimer_new(sock->base->base, cancelcb, sock);
		event_add(sock->event_cancel, &val);
	}
}

int co_socket_connect(co_socket* sock, const char* sz_addr, int port) {
	timeval val = {sock->write_timeout, 0};
	int error = 0;	
	socklen_t len_err = sizeof(int);
	sockaddr_in addr = {};
	addr.sin_addr.s_addr = inet_addr(sz_addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	int ret = connect(sock->fd, (sockaddr*)&addr, sizeof(addr));
	if(ret == 0) {
		return 0;
	}

	if(ret < 0 && errno != EINPROGRESS) {
		return -1;
	}

	sock->event_write = event_new(sock->base->base, sock->fd, EV_WRITE, conncb, sock);
	sock->write_task_id = coroutine_running(sock->base->sch);
	event_add(sock->event_write, sock->write_timeout == -1 ? NULL : &val);
	coroutine_yield(sock->base->sch);

	if(sock->is_task_canceled) {
		return -1;
	}

	if(sock->is_write_timeout) {
		return -1;
	}
	getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &error, &len_err);
	event_free(sock->event_write);
	sock->event_write = NULL;
	return error;
}

co_socket* co_socket_accept(co_socket* sock) {
	co_socket* sock_ret = NULL;
	if(!sock->event_read) {
		sock->event_read = event_new(sock->base->base, sock->fd, EV_READ, acceptcb, sock);
	}
retry:
	sock->accept_task_id = coroutine_running(sock->base->sch);

	event_add(sock->event_read, NULL);

	coroutine_yield(sock->base->sch);

	if(sock->is_task_canceled) {
		sock->is_error = true;
		return NULL;
	}

	fprintf(stderr, "accept listener fd=%d\n", sock->fd);
	int fd = accept(sock->fd, NULL, NULL);
	sock->read_task_id  = -1;
	fprintf(stderr, "accept client fd=%d\n",fd);
	if(fd < 0) {

		if(errno == EAGAIN) {
			goto retry;
		} else {
			fprintf(stderr, "accept ret -1, errono=%d\n", errno);
			return NULL;
		}		
	}
	evutil_make_socket_nonblocking(fd);
	sock_ret = (co_socket*)calloc(1, sizeof(co_socket));
	sock_ret->fd = fd;
	sock_ret->base = sock->base;
	list_add(&sock_ret->list, &s_head);
	return sock_ret;
}

int co_socket_read_peek(co_socket* sock, char* buf, int len) {
	int len_read = 0;

	len_read = recv(sock->fd, buf, len, MSG_PEEK);
	printf("len read =%d\n", len_read);
	if(len_read >= 0) {
		return len_read;
	}

	if(len_read < 0 && errno != EAGAIN) {
		sock->is_error = true;
		return len_read;
	}

	if(!sock->event_read) {
		sock->event_read = event_new(sock->base->base, sock->fd, EV_READ, readcb, sock);
	}

	sock->read_task_id = coroutine_running(sock->base->sch);
	event_add(sock->event_read, NULL);
	coroutine_yield(sock->base->sch);

	if(sock->is_task_canceled) {
		return -1;
	}

	len_read = recv(sock->fd, buf, len, MSG_PEEK);

	if(len_read <= 0) {
		sock->is_error = true;
	}
	return len_read;
}


int co_socket_read(co_socket* sock, char* buf, int len) {

	if(sock->is_task_canceled) {
		return -1;
	}

	if(sock->is_read_timeout) {
		return -1;
	}

	if(sock->is_error) {
		return -1;
	}

	int len_read = 0;
	timeval val = {sock->read_timeout, 0};
	len_read = recv(sock->fd, buf, len, 0);
	printf("len read =%d\n", len_read);
	if(len_read >= 0) {
		return len_read;
	}

	if(len_read < 0 && errno != EAGAIN) {
		sock->is_error = true;
		return len_read;
	}

	if(!sock->event_read) {
		sock->event_read = event_new(sock->base->base, sock->fd, EV_READ, readcb, sock);
	}

	sock->read_task_id = coroutine_running(sock->base->sch);
	event_add(sock->event_read, sock->read_timeout == -1 ? NULL : &val);
	coroutine_yield(sock->base->sch);

	if(sock->is_task_canceled) {
		return -1;
	}

	if(sock->is_read_timeout) {
		return -1;
	}

	len_read = recv(sock->fd, buf, len, 0);
	printf("read ret %d\n", len_read);
	if(len_read <= 0) {
		sock->is_error = true;
	}
	return len_read;
}

char* memstr(char* full_data, int full_data_len, char* substr)
{
    if (full_data == NULL || full_data_len <= 0 || substr == NULL) {
        return NULL;
    }

    if (*substr == '0') {
        return NULL;
    }

    int sublen = strlen(substr);

    int i;
    char* cur = full_data;
    int last_possible = full_data_len - sublen + 1;
    for (i = 0; i < last_possible; i++) {
        if (*cur == *substr) {
            //assert(full_data_len - i >= sublen);
            if (memcmp(cur, substr, sublen) == 0) {
                //found
                return cur;
            }
        }
        cur++;
    }

    return NULL;
}

int co_socket_readline(co_socket* sock, char* buf, int len) {
	memset(buf, 0, len);
	timeval val = {sock->read_timeout, 0};
	int len_in_readbuf = recv(sock->fd, buf, len - 1, MSG_PEEK);
	printf("len_in_readbuf = %d\n", len_in_readbuf);
	if(!sock->event_read) {
		sock->event_read = event_new(sock->base->base, sock->fd, EV_READ, readcb, sock);
	}

	sock->read_task_id = coroutine_running(sock->base->sch);

	for(;;) {
		event_add(sock->event_read,  sock->read_timeout == -1 ? NULL : &val);
		coroutine_yield(sock->base->sch);
		printf("readline ret\n");
		if(sock->is_task_canceled) {
			printf("task canceled\n");
			sock->is_error = true;
			return -1;
		}
		memset(buf, 0, len);
		len_in_readbuf = recv(sock->fd, buf, len - 1, MSG_PEEK);
 		//printf("len in peek readbuf = %d,data=%s\n", len_in_readbuf, buf);
		if(len_in_readbuf <= 0) {
			printf("len in readbuf = %d\n", len_in_readbuf);
			sock->is_error = true;
			return -1;
		}
		
		char* pos = memstr(buf, len_in_readbuf, "\r\n");
		bool is_single = false;
		if(!pos) {
		    pos = strstr(buf, "\n");
	//	    if(pos) is_single = true;
		}
		if(pos) {
			int len_line = pos - buf;
			const int extra_len = is_single ? 1 : 2;
			recv(sock->fd, buf, len_line + extra_len, 0);
			buf[len_line] = '\0';
			printf("len_line=%d,line=%s\n", len_line, buf);
			return len_line;
		} else if(len_in_readbuf >= len - 1) {
			printf("\r\n not found");
			sock->is_error = true;
			return -1;
		} else {
			printf("other\n");
		}
	}
}

int co_socket_write(co_socket* sock, char* buf, int len) {
	const int write_len_once = 4096;
	char* buf_tmp = buf;
	int ret;
	socklen_t len_ret = sizeof(ret);
	getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &ret, &len_ret);

	if(ret != 0) {
		return -1;
	}
	 
	int write_len = 0;
	for(;;) {
		if(sock->is_error) {
			return -1;
		}
		if(sock->is_task_canceled) {
			sock->is_error = true;
			return -1;
		}

		int len_to_write = len - write_len < write_len_once ? len - write_len : write_len_once;
		int len_real_write = send(sock->fd, buf_tmp + write_len, len_to_write, 0);
		printf("write ret %d, towrite = %d\n", len_real_write, len);
		if(len_real_write < 0) {
			if(errno == EAGAIN) {
				if(buf_tmp == buf) {
					buf_tmp = new char[len];
					memcpy(buf_tmp, buf, len);
				}

				if(!sock->event_write) {
					sock->event_write = event_new(sock->base->base, sock->fd, EV_WRITE, writecb, sock);
				}
				event_add(sock->event_write, NULL);
				sock->write_task_id = coroutine_running(sock->base->sch);
				coroutine_yield(sock->base->sch);

				if(sock->is_task_canceled) {
					sock->is_error = true;
					return -1;
				}

				continue;
			} else {
				printf("write error detect\n");
				sock->is_error = true;
				write_len = -1;
				break;
			}
		}
		write_len += len_real_write;
		if(len_real_write < len_to_write) {
			if(buf_tmp == buf) {
					buf_tmp = new char[len];
					memcpy(buf_tmp, buf, len);
			}

			if(!sock->event_write) {
				sock->event_write = event_new(sock->base->base, sock->fd, EV_WRITE, writecb, sock);
			}
			sock->write_task_id = coroutine_running(sock->base->sch);
			event_add(sock->event_write, NULL);
			printf("write coroutine_yield\n");
			coroutine_yield(sock->base->sch);
			printf("write coroutine_yield ret\n");
			if(sock->is_task_canceled) {
				printf("task canceled\n");
				if(buf_tmp != buf) {
					delete[] buf_tmp;
				}
				sock->is_error = true;
				return -1;
			}
			continue;
		}

		if(write_len == len) {
			break;
		}

	}

	if(buf_tmp != buf) {
		delete[] buf_tmp;
	}

	return write_len;
}

int co_socket_detach_fd(co_socket* sock) {
	int tmp = sock->fd;
	sock->fd = 0;
	list_del(&sock->list);
	return tmp;
}
int co_socket_get_fd(co_socket* sock) {
	return sock->fd;;
}

void co_socket_close(co_socket* sock) {
	if(sock->fd) {
		list_del(&sock->list);
		close(sock->fd);
	}
	if(sock->event_write) {
		if(event_pending(sock->event_write, EV_WRITE, NULL)) {
			event_del(sock->event_write);
		}
		event_free(sock->event_write);
	}

	if(sock->event_read) {
		if(event_pending(sock->event_read, EV_WRITE, NULL)) {
			event_del(sock->event_read);
		}
		event_free(sock->event_read);
	}
	
	if(sock->event_cancel) {
		if(event_pending(sock->event_cancel, EV_WRITE, NULL)) {
			event_del(sock->event_cancel);
		}
		event_free(sock->event_cancel);
	}
	free(sock);
}

bool co_socket_is_error(co_socket* sock) {
	return sock->is_error;
}
