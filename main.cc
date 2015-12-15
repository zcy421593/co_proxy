#include "co_base.h"
#include "co_thread.h"
#include "co_socket.h"
#include <vector>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "dns.h"
#include "http_parser.h"
#include "utils.h"
#include "conn_pool.h"
#include "http_upstream.h"
#include "http_downstream.h"
using namespace std;

struct relay_info {
	co_socket* sock_read;
	co_socket* sock_send;
};
static void* relay_cb(co_thread* thread, void* args) {
	char buf[4096] = {};
	relay_info* info = (relay_info*)args;
	for(;;) {
		int ret = co_socket_read(info->sock_read, buf, sizeof(buf));
		if(ret <= 0) {
			break;
		}
		ret = co_socket_write(info->sock_send, buf, ret);
		if(ret <= 0) {
			break;
		}
	}
	return NULL;
}


static void* connect_cb(co_thread* thread, void* args) {
	bool err = false;
	char buf[4096] = {};
	co_base* base = co_thread_get_base(thread);
	co_socket* sock_client = (co_socket*)args;
	for(;;) {
		bool do_continue = true;
		http_upstream* upstream = NULL;
		http_downstream* downstream = NULL;
		http_response_header* resp_hdr = NULL;
		upstream = new http_upstream(base, sock_client);
		http_request_header* req_hdr = upstream->read_header();
		int status_code = 0;
		if(!req_hdr) {
			do_continue = false;
			goto complete_session;
		}

		if(req_hdr->method == "CONNECT") {
			const char* resp_str= "HTTP/1.1 200 Establish\r\n\r\n";
			co_socket_write(sock_client, (char*)resp_str, strlen(resp_str));
			co_socket* sock_relay = co_socket_create(base);
			const char* ip = dns_resolve(req_hdr->url_host.c_str());

			if(!ip) {
				co_socket_close(sock_relay);
				do_continue = false;
				goto complete_session;
			}

			if(co_socket_connect(sock_relay, ip, req_hdr->url_port) != 0) {
				co_socket_close(sock_relay);
				do_continue = false;
				goto complete_session;
			}
			relay_info* relay1 = new relay_info;
			relay1->sock_read = sock_client;
			relay1->sock_send = sock_relay;
			relay_info* relay2 = new relay_info;
			relay2->sock_read = sock_relay;
			relay2->sock_send = sock_client;

			co_thread* thread_relay1 = co_thread_create(base, relay_cb, relay1);
			co_thread* thread_relay2 = co_thread_create(base, relay_cb, relay2);
			co_thread_join(thread_relay1);
			co_thread_join(thread_relay2);
			delete relay1;
			delete relay2;
			co_thread_free(thread_relay1);
			co_thread_free(thread_relay2);
			co_socket_close(sock_relay);
			do_continue = false;
			goto complete_session;
		}

		if(req_hdr->method == "POST" || req_hdr->method == "PUT") {
			if(req_hdr->content_length.empty() && req_hdr->transfer_encoding.empty()) {
				do_continue = false;
				goto complete_session;
			}
		}

		downstream = new http_downstream(base, req_hdr);
		if(downstream->connect() != 0) {
			do_continue = false;
			goto complete_session;
		}
		downstream->write_request_header();

		if(req_hdr->get_header_value("Expect") == "100-continue") {
			const char* resp_str= "HTTP/1.1 100 CONTINUE\r\n\r\n";
			co_socket_write(sock_client, (char*)resp_str, strlen(resp_str));
		}

		if(req_hdr->method == "POST" || req_hdr->method == "PUT") {
			bool err = false;
			for(;;) {
				int len_read = upstream->read_body(buf, sizeof(buf));
				if(len_read < 0) {
					err = true;
					break;
				} else if(len_read ==0) {
					downstream->complete_body();
					break;
				} else {
					downstream->write_body(buf, len_read);
				}
			}

			if(err) {
				do_continue = false;
				goto complete_session;
			}
		}
read_hdr:
		resp_hdr = downstream->read_response_header();
		if(!resp_hdr) {
			do_continue = false;
			goto complete_session;
		}

		if(resp_hdr->status_code == "100") {
			delete resp_hdr;
			goto read_hdr;
		}
		printf("status code=%s\n", resp_hdr->status_code.c_str());
		
		if(upstream->write_response_header(resp_hdr) < 0) {
			do_continue = false;
			goto complete_session;
		}

		status_code = atoi(resp_hdr->status_code.c_str());
		if(req_hdr->method == "HEAD" ||
		   (status_code > 100 && status_code <200) ||
		   status_code == 204 ||
		   status_code == 304) {
		   	do_continue = false;
			goto complete_session;
		}

		
		for(;;) {
			int len_read = downstream->read_body(buf, sizeof(buf));
			printf("downstream readbody ret:%d\n", len_read);
			if(len_read < 0) {
				err = true;
				break;
			} else if(len_read ==0) {
				if(upstream->complete_body() < 0) {
					err = true;
				}
				break;
			} else {
				if(upstream->write_body(buf, len_read) < 0) {
					err = true;
					break;
				}
			}
		}

		if(err || resp_hdr->version_str != "HTTP/1.1") {
			do_continue = false;
		}

		if(resp_hdr->get_header_value("Connection") == "close") {
			do_continue = false;
		}

		if(resp_hdr->get_header_value("Proxy-Connection") == "close") {
			do_continue = false;
		}

complete_session:
		if(upstream) {
			delete upstream;
			upstream = NULL;
		}

		if(downstream) {
			delete downstream;
			downstream = NULL;
		}
		
		if(!do_continue) {
			break;
		}
		
	}
	co_socket_close(sock_client);
	printf("write complete\n");
	return NULL;
}

void* listen_cb(co_thread* thread, void* args) {
	printf("listen start\n");
	co_base* base = co_thread_get_base(thread);
	co_socket* sock = co_socket_create(base);
	co_socket_bind(sock, "0.0.0.0", 8123);
	co_socket_listen(sock, 5);
	while(1) {
		co_socket* sock_client = co_socket_accept(sock);
		printf("accept a client\n");
		if(!sock_client) {
			return NULL;
		}
		co_thread* th1 = co_thread_create(base, connect_cb, sock_client);
		co_thread_detach(th1);
	}
	return NULL;
}

int main() {
	signal(SIGPIPE, SIG_IGN);
	co_base* base = co_base_create();
	dns_init(base, "114.114.114.114");
	printf("dns init complete\n");
	co_thread* thread_listen = co_thread_create(base, listen_cb, NULL);
	co_thread_detach(thread_listen);
	co_base_dispatch(base);
}
