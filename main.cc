#include "co_base.h"
#include "co_thread.h"
#include "co_socket.h"
#include <vector>
#include <string>

using namespace std;
void* client_routing(co_thread* thread, void* args) {
	co_socket* sock = (co_socket*)args;
	evbuffer* evbuf = evbuffer_new();
	char readbuf[4096] = {};
	while(1) {
		int len = 0;
		len = co_socket_readline(sock, readbuf, sizeof(readbuf));
		if(len < 0) {
			printf("connection closed, or data error\n");
			break;
		}
		printf("line=%s\n", readbuf);
	}
	return NULL;
}

void* listen_cb(co_thread* thread, void* args) {
	printf("listen start\n");
	co_base* base = co_thread_get_base(thread);
	co_socket* sock = co_socket_create(base);
	co_socket_bind(sock, "127.0.0.1", 8123);
	co_socket_listen(sock, 5);
	while(1) {
		co_socket* sock_client = co_socket_accept(sock);
		printf("accept a client\n");
		if(!sock_client) {
			break;
		}
		co_thread* th = co_thread_create(base, client_routing, sock_client);
		co_thread_detach(th);
	}
	return NULL;
}

int main() {
	co_base* base = co_base_create();
	co_thread* thread_listen = co_thread_create(base, listen_cb, NULL);
	co_base_dispatch(base);
}
